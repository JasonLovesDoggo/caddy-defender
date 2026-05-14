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

	clientIP, err := clientIPFromRequest(r)
	if err != nil {
		m.log.Error("Invalid client IP", zap.String("remote_addr", r.RemoteAddr), zap.Error(err))
		return caddyhttp.Error(http.StatusForbidden, err)
	}
	m.log.Debug("Ranges", zap.Strings("ranges", m.Ranges))

	// Check if the client IP should be allowed (considering whitelist and blocked ranges)
	if m.ipChecker.ReqAllowed(r.Context(), clientIP) {
		m.log.Debug("Request allowed (IP whitelisted or not in blocked ranges)", zap.String("ip", clientIP.String()))
		// Request is allowed, proceed to the next handler
		return next.ServeHTTP(w, r)
	}
	m.log.Debug("Request blocked (IP in blocked ranges and not whitelisted)", zap.String("ip", clientIP.String()))
	// Request should be blocked
	return m.responder.ServeHTTP(w, r, next)
}

func clientIPFromRequest(r *http.Request) (net.IP, error) {
	if clientIP, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && clientIP != "" {
		return parseClientIP(clientIP)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid client IP format")
	}
	return parseClientIP(host)
}

func parseClientIP(rawIP string) (net.IP, error) {
	clientIP := net.ParseIP(rawIP)
	if clientIP == nil {
		return nil, fmt.Errorf("invalid client IP")
	}
	return clientIP, nil
}
