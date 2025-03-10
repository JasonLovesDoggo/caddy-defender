package caddydefender

import (
	"fmt"
	"net"
	"net/http"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// serveIgnore is a helper function to serve a robots.txt file if the ServeIgnore option is enabled.
// It returns true if the request was handled, false otherwise.
func (m Defender) serveGitignore(w http.ResponseWriter, r *http.Request) bool {
	m.log.Debug("ServeIgnore",
		zap.Bool("serveIgnore", m.ServeIgnore),
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
	)

	// Serve robots.txt only if ServeIgnore is enabled, the path is "/robots.txt", and the method is GET.
	if !m.ServeIgnore || r.URL.Path != "/robots.txt" || r.Method != http.MethodGet {
		return false
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	// Build the robots.txt content to allow specific bots and block others.
	robotsTxt := `
User-agent: Googlebot
Disallow:

User-agent: Bingbot
Disallow:

User-agent: DuckDuckBot
Disallow:

User-agent: *
Disallow: /
`
	_, _ = w.Write([]byte(robotsTxt))
	return true
}

// ServeHTTP implements the middleware logic.
func (m Defender) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if m.serveGitignore(w, r) {
		return nil
	}
	// Split the RemoteAddr into IP and port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.log.Error("Invalid client IP format", zap.String("ip", r.RemoteAddr))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP format"))
	}

	clientIP := net.ParseIP(host)
	if clientIP == nil {
		m.log.Error("Invalid client IP", zap.String("ip", host))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP"))
	}
	m.log.Debug("Ranges", zap.Strings("ranges", m.Ranges))
	// Check if the client IP is in any of the ranges using the optimized checker
	if m.ipChecker.ReqAllowed(r.Context(), clientIP) {
		m.log.Debug("IP is not in ranges", zap.String("ip", clientIP.String()))
	} else {
		m.log.Debug("IP is in ranges", zap.String("ip", clientIP.String()))
		return m.responder.ServeHTTP(w, r, next)
	}

	// IP is not in any of the ranges, proceed to the next handler
	return next.ServeHTTP(w, r)
}
