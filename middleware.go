package caddydefender

import (
	"fmt"
	"go.uber.org/zap"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ServeHTTP implements the middleware logic.
func (m Defender) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
