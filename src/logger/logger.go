package logger

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	LevelMinimum = iota
	LevelNormal
	LevelMaximum
)

var (
	mu       sync.RWMutex
	progName string
	logLevel int
)

func SetProgramName(name string) {
	mu.Lock()
	progName = name
	mu.Unlock()
}

// SetLoggingLevel sets the logging verbosity level.
// "minimum" = LevelMinimum (auth failures only)
// "normal" = LevelNormal (+ auth successes)
// "maximum" = LevelMaximum (+ authz successes)
func SetLoggingLevel(level string) {
	mu.Lock()
	switch {
	case level == "minimum", level == "MINIMUM":
		logLevel = LevelMinimum
	case level == "maximum", level == "MAXIMUM":
		logLevel = LevelMaximum
	default:
		// default to "normal"
		logLevel = LevelNormal
	}
	mu.Unlock()
}

// GetLoggingLevel returns the current logging level.
func GetLoggingLevel() int {
	mu.RLock()
	defer mu.RUnlock()
	return logLevel
}

// ExtractClientIP extracts the actual client IP from an HTTP request.
// It checks X-Forwarded-For and X-Real-IP headers for proxied requests,
// falling back to RemoteAddr if neither header is present.
func ExtractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (used by Nginx, etc.)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs; the first one is the original client
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (alternative proxy header)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr if no proxy headers are present
	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	return clientIP
}

func LogWithTime(format string, v ...interface{}) {
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	msg := fmt.Sprintf(format, v...)

	mu.RLock()
	pname := progName
	mu.RUnlock()

	var out string
	if pname != "" {
		out = fmt.Sprintf("%s [%s] %s", timestamp, pname, msg)
	} else {
		out = fmt.Sprintf("%s %s", timestamp, msg)
	}

	log.Print(out)
}
