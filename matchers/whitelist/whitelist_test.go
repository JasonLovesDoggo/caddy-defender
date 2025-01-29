package whitelist

import (
	"net/netip"
	"testing"
)

func TestNewWhitelist(t *testing.T) {
	tests := []struct {
		name        string
		ipStrings   []string
		expectError bool
	}{
		{
			name:        "Valid IPv4 and IPv6",
			ipStrings:   []string{"192.168.1.1", "2001:db8::1"},
			expectError: false,
		},
		{
			name:        "Invalid IP",
			ipStrings:   []string{"invalid-ip"},
			expectError: true,
		},
		{
			name:        "Mixed valid and invalid IPs",
			ipStrings:   []string{"192.168.1.1", "invalid-ip"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl, err := NewWhitelist(tt.ipStrings)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error for invalid IPs, but got nil")
				}
				if wl != nil {
					t.Error("Expected whitelist to be nil on error, but it was not")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid IPs: %v", err)
				}
				if wl == nil {
					t.Error("Expected whitelist to be non-nil, but got nil")
				}
			}
		})
	}
}

func TestWhitelisted(t *testing.T) {
	wl, err := NewWhitelist([]string{"192.168.1.1", "2001:db8::1"})
	if err != nil {
		t.Fatalf("Failed to create whitelist: %v", err)
	}

	tests := []struct {
		name     string
		ip       netip.Addr
		expected bool
	}{
		{
			name:     "IPv4 in whitelist",
			ip:       netip.MustParseAddr("192.168.1.1"),
			expected: true,
		},
		{
			name:     "IPv6 in whitelist",
			ip:       netip.MustParseAddr("2001:db8::1"),
			expected: true,
		},
		{
			name:     "IPv4 not in whitelist",
			ip:       netip.MustParseAddr("192.168.1.2"),
			expected: false,
		},
		{
			name:     "IPv6 not in whitelist",
			ip:       netip.MustParseAddr("2001:db8::2"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wl.Whitelisted(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %v, but got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

func TestValidateWhitelist(t *testing.T) {
	tests := []struct {
		name        string
		ipStrings   []string
		expectError bool
	}{
		{
			name:        "Valid IPv4 and IPv6",
			ipStrings:   []string{"192.168.1.1", "2001:db8::1"},
			expectError: false,
		},
		{
			name:        "Invalid IP",
			ipStrings:   []string{"invalid-ip"},
			expectError: true,
		},
		{
			name:        "Mixed valid and invalid IPs",
			ipStrings:   []string{"192.168.1.1", "invalid-ip"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWhitelist(tt.ipStrings)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error for invalid IPs, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid IPs: %v", err)
				}
			}
		})
	}
}
