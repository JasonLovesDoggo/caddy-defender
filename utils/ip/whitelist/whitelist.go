package whitelist

import (
	"fmt"
	"net/netip"
)

// Whitelist holds the allowed IP addresses.
type Whitelist struct {
	ips map[netip.Addr]struct{} // Use netip.Addr for efficient IP handling
}

// NewWhitelist initializes a new Whitelist from IP strings.
func NewWhitelist(ipStrings []string) (*Whitelist, error) {
	wl := &Whitelist{
		ips: make(map[netip.Addr]struct{}),
	}
	for _, ipStr := range ipStrings {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		wl.ips[ip] = struct{}{}
	}
	return wl, nil
}

// Whitelisted checks if the remote address is in the whitelist.
func (wl *Whitelist) Whitelisted(ip netip.Addr) bool {
	// Check if the IP is in the whitelist
	_, ok := wl.ips[ip]
	return ok
}

// ValidateWhitelist checks if a list of IP strings are valid.
func ValidateWhitelist(ipStrings []string) error {
	for _, ipStr := range ipStrings {
		_, err := netip.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}
	}
	return nil
}
