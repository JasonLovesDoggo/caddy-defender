package ip

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
)

// ipToAddrStd is the function under test
func ipToAddrStd(ip net.IP) (netip.Addr, error) {
	if ip == nil {
		return netip.Addr{}, fmt.Errorf("ip is nil")
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}
	return addr, nil
}

func TestIPToAddrStd(t *testing.T) {
	tests := []struct {
		name        string
		ip          net.IP
		expected    netip.Addr
		expectError bool
	}{
		{
			name:        "Valid IPv4",
			ip:          net.ParseIP("192.168.1.1"),
			expected:    netip.MustParseAddr("::ffff:192.168.1.1"),
			expectError: false,
		},
		{
			name:        "Valid IPv6",
			ip:          net.ParseIP("2001:db8::1"),
			expected:    netip.MustParseAddr("2001:db8::1"),
			expectError: false,
		},
		{
			name:        "Nil IP",
			ip:          nil,
			expected:    netip.Addr{},
			expectError: true,
		},
		{
			name:        "Empty IP",
			ip:          net.IP{},
			expected:    netip.Addr{},
			expectError: true,
		},
		{
			name:        "Invalid IP (too short)",
			ip:          net.IP{1, 2, 3}, // Invalid length
			expected:    netip.Addr{},
			expectError: true,
		},
		{
			name:        "Invalid IP (too long)",
			ip:          net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}, // Invalid length
			expected:    netip.Addr{},
			expectError: true,
		},
		{
			name:        "IPv4-Mapped IPv6",
			ip:          net.ParseIP("::ffff:192.168.1.1"),
			expected:    netip.MustParseAddr("::ffff:192.168.1.1"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := ipToAddrStd(tt.ip)

			// Check if an error was expected
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, but got none")
				}
				return
			}

			// If no error was expected, check the result
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if addr != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, addr)
			}
		})
	}
}
