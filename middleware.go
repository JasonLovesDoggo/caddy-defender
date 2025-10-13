package caddydefender

import (
	"bufio"
	"fmt"
	"net"
	"net/http"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"pkg.jsn.cam/caddy-defender/ratelimit"
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

	// Wrap response writer to capture status code for rate limiting
	var recorder *ratelimit.ResponseRecorder
	if m.rateLimitTracker != nil {
		recorder = ratelimit.NewResponseRecorder(w)
		w = recorder
	}

	// IP is not in any of the ranges, proceed to the next handler
	err = next.ServeHTTP(w, r)

	// Track the request for rate limiting if enabled
	if m.rateLimitTracker != nil && recorder != nil {
		exceeded, trackErr := m.rateLimitTracker.TrackRequest(clientIP, recorder.StatusCode)
		if trackErr != nil {
			m.log.Error("Failed to track request for rate limiting",
				zap.String("ip", clientIP.String()),
				zap.Error(trackErr))
		}

		// If rate limit exceeded, add IP to blocklist
		if exceeded && m.RateLimitConfig.AutoAddToBlocklist {
			if addErr := m.addIPToBlocklist(clientIP); addErr != nil {
				m.log.Error("Failed to add IP to blocklist",
					zap.String("ip", clientIP.String()),
					zap.Error(addErr))
			} else {
				m.log.Info("Added IP to blocklist due to rate limit violation",
					zap.String("ip", clientIP.String()),
					zap.Int("status_code", recorder.StatusCode))

				// Block this request immediately (Option A)
				return m.responder.ServeHTTP(recorder.ResponseWriter, r, next)
			}
		}
	}

	return err
}

// addIPToBlocklist adds an IP address to the blocklist file (if configured)
func (m *Defender) addIPToBlocklist(clientIP net.IP) error {
	if m.BlocklistFile == "" {
		return fmt.Errorf("blocklist_file not configured")
	}

	// Convert IP to CIDR format
	ipCIDR := fmt.Sprintf("%s/32", clientIP.String())
	if clientIP.To4() == nil {
		// IPv6
		ipCIDR = fmt.Sprintf("%s/128", clientIP.String())
	}

	// Use the DefenderAdmin's addIPsToFile method
	globalAdminMu.RLock()
	admin := globalDefenderAdmin
	globalAdminMu.RUnlock()

	if admin == nil {
		return fmt.Errorf("DefenderAdmin not available")
	}

	return admin.addIPsToFile(m.BlocklistFile, []string{ipCIDR})
}
