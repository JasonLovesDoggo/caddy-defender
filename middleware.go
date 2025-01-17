package caddydefender

import (
	"bufio"
	"fmt"
	"go.uber.org/zap"
	"net"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jasonlovesdoggo/caddy-defender/utils"
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
	m.log.Debug("client IP", zap.String("ip", clientIP.String()))
	if clientIP == nil {
		m.log.Error("Invalid client IP", zap.String("ip", host))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid client IP"))
	}

	// Check if the client IP is in any of the additional ranges
	if utils.IPInRanges(clientIP, m.AdditionalRanges, m.log) {
		return m.responder.Respond(w, r)
	}

	// Check if the client IP is in any of the ranges loaded from the text file
	if m.RangesFile != "" {
		file, err := os.Open(m.RangesFile)
		if err != nil {
			m.log.Error("Failed to open ranges file", zap.String("file", m.RangesFile))
			return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to open ranges file"))
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				m.log.Error("Invalid IP range in file", zap.String("range", line))
				continue
			}
			if ipNet.Contains(clientIP) {
				return m.responder.Respond(w, r)
			}
		}

		if err := scanner.Err(); err != nil {
			m.log.Error("Error reading ranges file", zap.String("file", m.RangesFile))
			return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("error reading ranges file"))
		}
	}

	// IP is not in any of the ranges, proceed to the next handler
	return next.ServeHTTP(w, r)
}
