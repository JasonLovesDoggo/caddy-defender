package ip

import (
	"fmt"
	"net"
)

type Whitelist struct {
	ips map[string]struct{}
}

// NewWhitelist initializes a new Whitelist from IP strings.
func NewWhitelist(ipStrings []string) (*Whitelist, error) {
	wl := &Whitelist{
		ips: make(map[string]struct{}),
	}
	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		wl.ips[ip16.String()] = struct{}{}
	}
	return wl, nil
}

// Allowed checks if the remote address is in the whitelist.
func (wl *Whitelist) Allowed(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Handle cases where there's no port
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false // Invalid IP format
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return false // Shouldn't happen if ParseIP succeeded
	}

	_, ok := wl.ips[ip16.String()]
	return ok
}

// Example usage in Caddy middleware:
// func (m YourModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
//     if !m.whitelist.Allowed(r.RemoteAddr) {
//         return caddyhttp.Error(http.StatusForbidden, nil)
//     }
//     return next.ServeHTTP(w, r)
// }
