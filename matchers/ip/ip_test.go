package ip

import (
	"context"
	"github.com/jasonlovesdoggo/skyfence/data"
	"net"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// Test data
var (
	validCIDRs = []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"2001:db8::/48", // Narrower range for IPv6 tests
		"openai",
	}
	invalidCIDRs = []string{
		"invalid-cidr",
		"192.168.1.0/33",
	}
	predefinedCIDRs = map[string][]string{
		"openai": {
			"203.0.113.0/24",
			"2001:db8:1::/48", // Specific IPv6 range
		},
	}
)

// Mock logger for testing
var testLogger = zap.NewNop()

func TestIPInRanges(t *testing.T) {
	// Mock predefined CIDRs
	originalIPRanges := data.IPRanges

	// Restore the original data.IPRanges map after the test
	defer func() {
		data.IPRanges = originalIPRanges
	}()
	data.IPRanges = predefinedCIDRs

	// Create a new IPChecker with valid CIDRs
	checker := NewIPChecker(validCIDRs, []string{}, testLogger)

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "IPv4 in range",
			ip:       "192.168.1.100",
			expected: true,
		},
		{
			name:     "IPv4 not in range",
			ip:       "192.168.2.100",
			expected: false,
		},
		{
			name:     "IPv6 in range",
			ip:       "2001:db8::1",
			expected: true,
		},
		{
			name:     "Predefined CIDR (IPv4)",
			ip:       "203.0.113.10",
			expected: true,
		},
		{
			name:     "Predefined CIDR (IPv6)",
			ip:       "2001:db8:1::10",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientIP := net.ParseIP(tt.ip)
			assert.NotNil(t, clientIP, "Failed to parse IP")
			ipAddr, err := ipToAddr(clientIP)
			assert.NoError(t, err, "Failed to convert IP to netip.Addr")

			result := checker.IPInRanges(context.Background(), ipAddr)
			assert.Equal(t, tt.expected, result, "Unexpected result for IP %s", tt.ip)
		})
	}
}

func TestIPInRangesCache(t *testing.T) {
	// Create a new IPChecker with valid CIDRs
	checker := NewIPChecker(validCIDRs, []string{}, testLogger)

	// Test IP
	clientIP := net.ParseIP("192.168.1.100")
	assert.NotNil(t, clientIP, "Failed to parse IP")
	ipAddr, err := ipToAddr(clientIP)
	assert.NoError(t, err, "Failed to convert IP to netip.Addr")
	// First call (not cached)
	result := checker.IPInRanges(context.Background(), ipAddr)
	assert.True(t, result, "Expected IP to be in range (first call)")

	// Second call (cached)
	result = checker.IPInRanges(context.Background(), ipAddr)
	assert.True(t, result, "Expected IP to be in range (second call)")
}

func TestIPInRangesCacheExpiration(t *testing.T) {
	// Create a new IPChecker with a short cache TTL for testing
	checker := NewIPChecker(validCIDRs, []string{}, testLogger)

	// Test IP
	clientIP := net.ParseIP("192.168.1.100")
	assert.NotNil(t, clientIP, "Failed to parse IP")
	ipAddr, err := ipToAddr(clientIP)
	assert.NoError(t, err, "Failed to convert IP to netip.Addr")

	// First call (not cached)
	result := checker.IPInRanges(context.Background(), ipAddr)
	assert.True(t, result, "Expected IP to be in range (first call)")

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Second call (cache expired)
	result = checker.IPInRanges(context.Background(), ipAddr)
	assert.True(t, result, "Expected IP to be in range (second call, cache expired)")
}

func TestIPInRangesInvalidCIDR(t *testing.T) {
	// Create a new IPChecker with invalid CIDRs
	checker := NewIPChecker(invalidCIDRs, []string{}, testLogger)

	// Test IP
	clientIP := net.ParseIP("192.168.1.100")
	assert.NotNil(t, clientIP, "Failed to parse IP")
	ipAddr, err := ipToAddr(clientIP)
	assert.NoError(t, err, "Failed to convert IP to netip.Addr")
	// Call with invalid CIDRs
	result := checker.IPInRanges(context.Background(), ipAddr)
	assert.False(t, result, "Expected IP to not be in range due to invalid CIDRs")
}

func TestIPInRangesInvalidIP(t *testing.T) {
	// Create a new IPChecker with valid CIDRs
	checker := NewIPChecker(validCIDRs, []string{}, testLogger)

	// Test invalid IP
	clientIP := net.IP([]byte{1, 2, 3}) // Invalid IP
	assert.NotNil(t, clientIP, "Failed to create invalid IP")

	ipAddr, err := ipToAddr(clientIP)
	assert.Error(t, err, "Failed to convert IP to netip.Addr")

	// Call with invalid IP
	result := checker.IPInRanges(context.Background(), ipAddr)
	assert.False(t, result, "Expected IP to not be in range due to invalid IP")
}

func TestPredefinedCIDRGroups(t *testing.T) {
	// Mock predefined CIDRs
	originalIPRanges := data.IPRanges
	defer func() { data.IPRanges = originalIPRanges }()
	data.IPRanges = map[string][]string{
		"cloud-providers": {
			"203.0.113.0/24",
			"2001:db8:1::/48",
		},
		"empty-group": {},
	}

	tests := []struct {
		name          string
		ip            string
		groups        []string
		expected      bool
		expectedError bool
	}{
		{
			name:     "IPv4 in predefined group",
			ip:       "203.0.113.42",
			groups:   []string{"cloud-providers"},
			expected: true,
		},
		{
			name:     "IPv6 in predefined group",
			ip:       "2001:db8:1::42",
			groups:   []string{"cloud-providers"},
			expected: true,
		},
		{
			name:     "IP not in group",
			ip:       "192.168.1.100",
			groups:   []string{"cloud-providers"},
			expected: false,
		},
		{
			name:          "Nonexistent group",
			ip:            "203.0.113.42",
			groups:        []string{"invalid-group"},
			expected:      false,
			expectedError: true,
		},
		{
			name:          "Empty group",
			ip:            "203.0.113.42",
			groups:        []string{"empty-group"},
			expected:      false,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			var logMessages []string
			logger := zap.NewExample(zap.Hooks(func(entry zapcore.Entry) error {
				logMessages = append(logMessages, entry.Message)
				return nil
			}))

			checker := NewIPChecker(tt.groups, []string{}, logger)
			clientIP := net.ParseIP(tt.ip)
			assert.NotNil(t, clientIP, "Failed to parse IP")

			ipAddr, err := ipToAddr(clientIP)
			assert.NoError(t, err, "Failed to convert IP to netip.Addr")

			result := checker.IPInRanges(context.Background(), ipAddr)
			assert.Equal(t, tt.expected, result, "Unexpected result for IP %s", tt.ip)

			// Verify error logging for problematic cases
			if tt.expectedError {
				assert.NotEmpty(t, logMessages, "Expected error logs but none found")
			} else {
				assert.Empty(t, logMessages, "Unexpected error logs: %v", logMessages)
			}
		})
	}
}
