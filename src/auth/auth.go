package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	logger "ngx-oauth2/logger"
)

const (
	LogLevelMinimum = iota
	LogLevelNormal
	LogLevelMaximum
)

type Config struct {
	IntrospectionEndpoint string
	ClientId              string
	ClientSecret          string
	AuthMethod            string
	SkipCertVerify        bool
	RootCaFiles           []string
	Timeout               int
}

var cfg Config

// SetConfig sets package config for OAuth2 introspection.
func SetConfig(c Config) {
	cfg = c
}

// logIfLevel logs only when current logging level >= requiredLevel
func logIfLevel(requiredLevel int, format string, v ...interface{}) {
	if logger.GetLoggingLevel() >= requiredLevel {
		logger.LogWithTime(format, v...)
	}
}

type introspectResult struct {
	Active   bool   `json:"active"`
	Username string `json:"username"`
	Scope    string `json:"scope"`
}

func buildHTTPClient() (*http.Client, error) {
	tr := &http.Transport{}
	if cfg.SkipCertVerify || len(cfg.RootCaFiles) > 0 {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipCertVerify}
		if len(cfg.RootCaFiles) > 0 {
			pool := x509.NewCertPool()
			for _, fn := range cfg.RootCaFiles {
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
	return &http.Client{Transport: tr, Timeout: time.Duration(cfg.Timeout) * time.Millisecond}, nil
}

// Authenticate performs token introspection and scope check.
// requiredScope may be empty to skip authorization check.
func Authenticate(token string, clientIP string, requiredScope string) (bool, bool, error) {
	client, err := buildHTTPClient()
	if err != nil {
		logger.LogWithTime("OAuth2 client build error: client_ip=%s err=%v", clientIP, err)
		return false, false, err
	}

	data := url.Values{}
	data.Set("token", token)
	req, err := http.NewRequest("POST", cfg.IntrospectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		logger.LogWithTime("OAuth2 request build error: client_ip=%s err=%v", clientIP, err)
		return false, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if strings.ToLower(cfg.AuthMethod) == "basic" {
		req.SetBasicAuth(cfg.ClientId, cfg.ClientSecret)
	} else {
		data.Set("client_id", cfg.ClientId)
		data.Set("client_secret", cfg.ClientSecret)
		req.Body = ioutil.NopCloser(strings.NewReader(data.Encode()))
		req.ContentLength = int64(len(data.Encode()))
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.LogWithTime("OAuth2 introspect error: client_ip=%s err=%v", clientIP, err)
		return false, false, err
	}
	defer resp.Body.Close()

	var ir introspectResult
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&ir); err != nil {
		logger.LogWithTime("OAuth2 introspect decode error: client_ip=%s err=%v", clientIP, err)
		return false, false, err
	}

	if !ir.Active {
		logger.LogWithTime("OAuth2 token inactive: client_ip=%s username=%s", clientIP, ir.Username)
		return false, false, nil
	}

	// Introspection success logged at normal level
	logIfLevel(LogLevelNormal, "OAuth2 introspect succeeded: username=%s client_ip=%s", ir.Username, clientIP)

	okAuthz := true
	if requiredScope != "" {
		scopes := strings.Fields(ir.Scope)
		found := false
		for _, s := range scopes {
			if s == requiredScope {
				found = true
				break
			}
		}
		okAuthz = found
	}

	if okAuthz && requiredScope != "" {
		logIfLevel(LogLevelMaximum, "OAuth2 authz succeeded: username=%s scope=%s required=%s client_ip=%s", ir.Username, ir.Scope, requiredScope, clientIP)
	} else if !okAuthz {
		logger.LogWithTime("OAuth2 authz failed: username=%s scope=%s required=%s client_ip=%s", ir.Username, ir.Scope, requiredScope, clientIP)
	}

	return true, okAuthz, nil
}
