package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/l4go/var_mtx"

	"ngx-oauth2/etag"
	"ngx-oauth2/logger"
)

func get_path_filter(rpath string) (bool, string) {
	pathid, ok := check_path(rpath)
	if !ok {
		if BanNomatch {
			return false, ""
		}
		return true, NomatchFilter
	}

	filter, has := PathFilter[pathid]
	if has {
		return true, filter
	}
	if BanDefault {
		return false, ""
	}
	return true, DefaultFilter
}

func check_path(rpath string) (string, bool) {
	if PathPatternReg == nil {
		return "", false
	}
	matchs := PathPatternReg.FindStringSubmatch(rpath)
	if len(matchs) < 1 {
		return "", false
	}

	return matchs[1], true
}

func http_not_auth(w http.ResponseWriter, _ *http.Request) {
	realm := strings.Replace(AuthRealm, `"`, `\"`, -1)
	w.Header().Add("WWW-Authenticate", `Bearer realm="`+realm+`"`)

	HttpResponse.Unauth.Error(w)
}

var userMtx = var_mtx.NewVarMutex()

// introspectResult models the subset of the OAuth2 introspection response we need
type introspectResult struct {
	Active   bool   `json:"active"`
	Username string `json:"username"`
	Scope    string `json:"scope"`
}

func buildHTTPClient() (*http.Client, error) {
	tr := &http.Transport{}
	if Oauth2Config.SkipCertVerify || len(Oauth2Config.RootCaFiles) > 0 {
		tlsCfg := &tls.Config{InsecureSkipVerify: Oauth2Config.SkipCertVerify}
		if len(Oauth2Config.RootCaFiles) > 0 {
			pool := x509.NewCertPool()
			for _, fn := range Oauth2Config.RootCaFiles {
				pem, err := ioutil.ReadFile(fn)
				if err != nil {
					return nil, err
				}
				pool.AppendCertsFromPEM(pem)
			}
			tlsCfg.RootCAs = pool
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{Transport: tr, Timeout: time.Duration(Oauth2Config.Timeout) * time.Millisecond}, nil
}

func introspectToken(token string) (*introspectResult, error) {
	client, err := buildHTTPClient()
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("token", token)
	req, err := http.NewRequest("POST", Oauth2Config.IntrospectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if strings.ToLower(Oauth2Config.AuthMethod) == "basic" {
		req.SetBasicAuth(Oauth2Config.ClientId, Oauth2Config.ClientSecret)
	} else {
		// client_secret_post
		data.Set("client_id", Oauth2Config.ClientId)
		data.Set("client_secret", Oauth2Config.ClientSecret)
		req.Body = ioutil.NopCloser(strings.NewReader(data.Encode()))
		req.ContentLength = int64(len(data.Encode()))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ir introspectResult
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&ir); err != nil {
		return nil, err
	}
	return &ir, nil
}

func auth_path(token string, path string, clientIP string) (bool, bool) {
	ok_path, path_filter := get_path_filter(path)
	if !ok_path {
		path_filter = ""
	}

	if UseSerializedAuth {
		userMtx.Lock(token)
		defer userMtx.Unlock(token)
	}

	ir, err := introspectToken(token)
	if err != nil {
		return false, false
	}
	if !ir.Active {
		return false, false
	}

	ok_auth := true
	ok_authz := true
	if path_filter != "" {
		// interpret path_filter as required scope
		scopes := strings.Fields(ir.Scope)
		req := path_filter
		found := false
		for _, s := range scopes {
			if s == req {
				found = true
				break
			}
		}
		ok_authz = found
	}

	if !ok_path {
		ok_authz = false
	}
	return ok_auth, ok_authz
}

func set_int64bin(bin []byte, v int64) {
	binary.LittleEndian.PutUint64(bin, uint64(v))
}

func makeEtag(ms int64, token, rpath string) string {
	pathid, ok := check_path(rpath)
	if ok {
		pathid = "M" + pathid
	} else {
		pathid = "N"
	}

	tm := make([]byte, 8)
	set_int64bin(tm, ms)

	return etag.Make(tm, etag.Crypt(tm, []byte(token)),
		etag.Hmac([]byte(token), []byte(token)), []byte(pathid))
}

func isModified(hd http.Header, org_tag string) bool {
	if_nmatch := hd.Get("If-None-Match")

	if if_nmatch != "" {
		return !isEtagMatch(if_nmatch, org_tag)
	}

	return true
}

func isEtagMatch(tag_str string, org_tag string) bool {
	tags, _ := etag.Split(tag_str)
	for _, tag := range tags {
		if tag == org_tag {
			return true
		}
	}

	return false
}

func TestAuthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	rpath := r.Header.Get(PathHeader)
	if rpath == "" {
		HttpResponse.Nopath.Error(w)
		return
	}

	// Accept Bearer token via Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http_not_auth(w, r)
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http_not_auth(w, r)
		return
	}
	token := parts[1]

	// Extract client IP, accounting for proxies (X-Forwarded-For, X-Real-IP)
	clientIP := logger.ExtractClientIP(r)

	if NegCacheSeconds > 0 {
		w.Header().Set("Cache-Control",
			fmt.Sprintf("max-age=%d, must-revalidate", NegCacheSeconds))
	}

	tag := makeEtag(StartTimeMS, token, rpath)
	w.Header().Set("Etag", tag)
	if UseEtag {
		if !isModified(r.Header, tag) {
			w.Header().Set("Etag", tag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	ok_auth, ok_authz := auth_path(token, rpath, clientIP)
	if !ok_auth {
		http_not_auth(w, r)
		return
	}
	if !ok_authz {
		HttpResponse.Forbidden.Error(w)
		return
	}

	if CacheSeconds > 0 {
		w.Header().Set("Cache-Control",
			fmt.Sprintf("max-age=%d, must-revalidate", CacheSeconds))
	}
	HttpResponse.Ok.Error(w)
}
