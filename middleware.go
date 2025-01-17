package caddydefender

import (
	"fmt"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jasonlovesdoggo/caddy-defender/utils"
	"go.uber.org/zap"
	"net"
	"net/http"
)

// ServeHTTP implements the middleware logic.
func (m *Defender) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Split the RemoteAddr into IP and port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.log.Error("Invalid client IP format", zap.String("ip", r.RemoteAddr))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP format"))
	}

	clientIP := net.ParseIP(host)
	m.log.Debug("client IP", zap.String("ip", clientIP.String()))
	if clientIP == nil {
		m.log.Error("Invalid client IP", zap.String("ip", host))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP"))
	}

	//Check if the client IP is in any of the ranges
	if utils.IPInRanges(clientIP, m.Ranges, m.log) {
		m.log.Debug("Blocked IP", zap.String("ip", clientIP.String()))
		return m.Responder.Respond(w, r)
	}

	// IP is not in any of the ranges, proceed to the next handler
	return next.ServeHTTP(w, r)
}
