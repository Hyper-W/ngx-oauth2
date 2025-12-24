package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/l4go/task"

	"ngx-oauth2/htstat"

	cfgloader "ngx-oauth2/config_loader"
	logger "ngx-oauth2/logger"
)

func die(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
	os.Exit(1)
}

func warn(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
}

type NgxLdapPathAuthConfig struct {
	SocketType        string `json:"socket_type" yaml:"socket_type"`
	SocketPath        string `json:"socket_path" yaml:"socket_path"`
	CacheSeconds      uint32 `toml:",omitempty" json:"cache_seconds,omitempty" yaml:"cache_seconds,omitempty"`
	NegCacheSeconds   uint32 `toml:",omitempty" json:"neg_cache_seconds,omitempty" yaml:"neg_cache_seconds,omitempty"`
	UseEtag           bool   `toml:",omitempty" json:"use_etag,omitempty" yaml:"use_etag,omitempty"`
	UseSerializedAuth bool   `toml:",omitempty" json:"use_serialized_auth,omitempty" yaml:"use_serialized_auth,omitempty"`
	AuthRealm         string `toml:",omitempty" json:"auth_realm,omitempty" yaml:"auth_realm,omitempty"`
	PathHeader        string `toml:",omitempty" json:"path_header,omitempty" yaml:"path_header,omitempty"`

	Oauth2 struct {
		IntrospectionEndpoint string   `json:"introspection_endpoint" yaml:"introspection_endpoint"`
		ClientId              string   `json:"client_id" yaml:"client_id"`
		ClientSecret          string   `json:"client_secret" yaml:"client_secret"`
		AuthMethod            string   `json:"auth_method" yaml:"auth_method"` // "basic" or "post"
		SkipCertVerify        int      `toml:",omitempty" json:"skip_cert_verify,omitempty" yaml:"skip_cert_verify,omitempty"`
		RootCaFiles           []string `toml:",omitempty" json:"root_ca_files,omitempty" yaml:"root_ca_files,omitempty"`
		Timeout               int      `toml:",omitempty" json:"timeout,omitempty" yaml:"timeout,omitempty"`
	} `json:"oauth2" yaml:"oauth2"`

	Authz struct {
		PathPattern   string            `json:"path_pattern" yaml:"path_pattern"`
		BanNomatch    bool              `toml:",omitempty" json:"ban_nomatch,omitempty" yaml:"ban_nomatch,omitempty"`
		NomatchFilter string            `toml:",omitempty" json:"nomatch_filter,omitempty" yaml:"nomatch_filter,omitempty"`
		BanDefault    bool              `toml:",omitempty" json:"ban_default,omitempty" yaml:"ban_default,omitempty"`
		DefaultFilter string            `toml:",omitempty" json:"default_filter,omitempty" yaml:"default_filter,omitempty"`
		PathFilter    map[string]string `toml:",omitempty" json:"path_filter,omitempty" yaml:"path_filter,omitempty"`
	} `json:"authz" yaml:"authz"`

	Response htstat.HttpStatusTbl `toml:",omitempty" json:"response,omitempty" yaml:"response,omitempty"`
	Logging  struct {
		EnableConsole bool   `toml:"enable_console,omitempty" json:"enable_console,omitempty" yaml:"enable_console,omitempty"`
		Logfile       string `toml:"logfile,omitempty" json:"logfile,omitempty" yaml:"logfile,omitempty"`
		LoggingLevel  string `toml:"logging_level,omitempty" json:"logging_level,omitempty" yaml:"logging_level,omitempty"`
	} `toml:"logging,omitempty" json:"logging,omitempty" yaml:"logging,omitempty"`
}

var SocketType string
var SocketPath string
var CacheSeconds uint32
var NegCacheSeconds uint32
var UseEtag bool
var UseSerializedAuth bool
var AuthRealm string

// OAuth2 runtime config (populated from config file)
type OAuth2Config struct {
	IntrospectionEndpoint string
	ClientId              string
	ClientSecret          string
	AuthMethod            string
	SkipCertVerify        bool
	RootCaFiles           []string
	Timeout               int
}

var Oauth2Config OAuth2Config

var PathHeader = "X-Authz-Path"
var PathPatternReg *regexp.Regexp

var UniqueFilter string
var BanNomatch bool
var NomatchFilter string
var BanDefault bool
var DefaultFilter string
var PathFilter map[string]string

var HttpResponse htstat.HttpStatusTbl

var StartTimeMS int64

func init() {
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s [options ...] <config_file>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.CommandLine.SetOutput(os.Stderr)

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	cfg_f, err := os.Open(flag.Arg(0))
	if err != nil {
		die("Config file open error: %s", err)
	}
	defer cfg_f.Close()

	cfg := &NgxLdapPathAuthConfig{}
	if err := cfgloader.LoadConfig(cfg_f, flag.Arg(0), cfg); err != nil {
		die("Config file parse error: %s", err)
	}

	if cfg.Logging.Logfile != "" {
		f, err := os.OpenFile(cfg.Logging.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logfile setting invalid: %v\n", err)
			if cfg.Logging.EnableConsole {
				log.SetOutput(os.Stdout)
			} else {
				log.SetOutput(io.Discard)
			}
		} else {
			if cfg.Logging.EnableConsole {
				log.SetOutput(io.MultiWriter(os.Stdout, f))
			} else {
				log.SetOutput(f)
			}
		}
	} else {
		if cfg.Logging.EnableConsole {
			log.SetOutput(os.Stdout)
		} else {
			log.SetOutput(io.Discard)
		}
	}

	progName := filepath.Base(os.Args[0])
	log.SetFlags(0)
	logger.SetProgramName(progName)
	logger.SetLoggingLevel(cfg.Logging.LoggingLevel)

	SocketType = cfg.SocketType
	SocketPath = cfg.SocketPath

	if SocketType != "tcp" && SocketType != "unix" {
		die("Bad socket type: %s", SocketType)
	}

	CacheSeconds = cfg.CacheSeconds
	NegCacheSeconds = cfg.NegCacheSeconds
	UseEtag = cfg.UseEtag
	UseSerializedAuth = cfg.UseSerializedAuth

	if cfg.AuthRealm == "" {
		die("relm is required")
	}
	AuthRealm = cfg.AuthRealm

	if cfg.PathHeader != "" {
		PathHeader = cfg.PathHeader
	}

	Oauth2Config = OAuth2Config{
		IntrospectionEndpoint: cfg.Oauth2.IntrospectionEndpoint,
		ClientId:              cfg.Oauth2.ClientId,
		ClientSecret:          cfg.Oauth2.ClientSecret,
		AuthMethod:            cfg.Oauth2.AuthMethod,
		SkipCertVerify:        cfg.Oauth2.SkipCertVerify != 0,
		RootCaFiles:           cfg.Oauth2.RootCaFiles,
		Timeout:               cfg.Oauth2.Timeout,
	}

	PathPatternReg, err = regexp.Compile(cfg.Authz.PathPattern)
	if err != nil {
		die("path pattern error: %s", cfg.Authz.PathPattern)
		return
	}

	BanNomatch = cfg.Authz.BanNomatch
	NomatchFilter = cfg.Authz.NomatchFilter
	if BanNomatch && NomatchFilter != "" {
		warn("nomatch_filter is not used because ban_nomatch is true.")
	}

	BanDefault = cfg.Authz.BanDefault
	DefaultFilter = cfg.Authz.DefaultFilter
	if BanDefault && DefaultFilter != "" {
		warn("default_filter is not used because ban_default is true.")
	}

	PathFilter = cfg.Authz.PathFilter

	cfg.Response.SetDefault()
	if !cfg.Response.IsValid() {
		die("response code config error.")
		return
	}
	HttpResponse = cfg.Response

	StartTimeMS = time.Now().UnixMicro()
}

var ErrUnsupportedSocketType = errors.New("unsupported socket type.")

func listen(cc task.Canceller, stype string, spath string) (net.Listener, error) {
	lcnf := &net.ListenConfig{}

	switch stype {
	default:
		return nil, ErrUnsupportedSocketType
	case "unix":
	case "tcp":
	}

	return lcnf.Listen(cc.AsContext(), stype, spath)
}

func main() {
	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{Addr: SocketPath}

	cc := task.NewCancel()
	defer cc.Cancel()
	go func() {
		select {
		case <-cc.RecvCancel():
		case <-signal_chan:
			cc.Cancel()
		}
		srv.Close()
	}()

	http.HandleFunc("/", TestAuthHandler)

	lstn, lerr := listen(cc, SocketType, SocketPath)
	switch lerr {
	case nil:
	case context.Canceled:
	default:
		die("socket listen error: %v.", lerr)
	}
	if SocketType == "unix" {
		defer os.Remove(SocketPath)
		os.Chmod(SocketPath, 0777)
	}

	if SocketType == "unix" {
		logger.LogWithTime("Server started: socket_type=unix socket_path=%s", SocketPath)
	} else {
		logger.LogWithTime("Server started: socket_type=tcp socket_path=%s", SocketPath)
	}

	serr := srv.Serve(lstn)
	switch serr {
	case nil:
	case http.ErrServerClosed:
	default:
		die("HTTP server error: %v.", serr)
	}
}
