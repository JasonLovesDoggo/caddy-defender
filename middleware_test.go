package caddydefender

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"pkg.jsn.cam/caddy-defender/responders"
)

// mockHandler is a simple handler that returns 200 OK
type mockHandler struct{}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
	return nil
}

func TestDefenderServeHTTP_WhitelistBehavior(t *testing.T) {
	tests := []struct {
		name           string
		ranges         []string
		whitelist      []string
		clientIP       string
		expectedStatus int
		description    string
	}{
		{
			name:           "IP in blocked range, not whitelisted - should be blocked",
			ranges:         []string{"192.168.1.0/24"},
			whitelist:      []string{},
			clientIP:       "192.168.1.100",
			expectedStatus: http.StatusForbidden,
			description:    "Should block IPs that are in blocked ranges and not whitelisted",
		},
		{
			name:           "IP not in any range - should be allowed",
			ranges:         []string{"192.168.1.0/24"},
			whitelist:      []string{},
			clientIP:       "10.0.0.1",
			expectedStatus: http.StatusOK,
			description:    "Should allow IPs that are not in any blocked ranges",
		},
		{
			name:           "IP in blocked range but whitelisted - should be ALLOWED (this is the bug)",
			ranges:         []string{"192.168.1.0/24"},
			whitelist:      []string{"192.168.1.100"},
			clientIP:       "192.168.1.100",
			expectedStatus: http.StatusOK,
			description:    "Should allow whitelisted IPs even if they are in blocked ranges",
		},
		{
			name:           "IP not in blocked range but whitelisted - should be allowed",
			ranges:         []string{"192.168.1.0/24"},
			whitelist:      []string{"10.0.0.1"},
			clientIP:       "10.0.0.1",
			expectedStatus: http.StatusOK,
			description:    "Should allow whitelisted IPs regardless of blocked ranges",
		},
		{
			name:           "Cloudflare range with whitelist - real world scenario",
			ranges:         []string{"cloudflare", "104.16.0.0/16"},
			whitelist:      []string{"173.245.48.1"},
			clientIP:       "173.245.48.1",
			expectedStatus: http.StatusOK,
			description:    "Should allow whitelisted Cloudflare IP even when Cloudflare range is blocked",
		},
		{
			name:           "IPv6 whitelist test",
			ranges:         []string{"2001:db8::/32"},
			whitelist:      []string{"2001:db8::1"},
			clientIP:       "[2001:db8::1]",
			expectedStatus: http.StatusOK,
			description:    "Should handle IPv6 whitelisting correctly",
		},
		{
			name:           "Multiple ranges with whitelist",
			ranges:         []string{"192.168.0.0/16", "10.0.0.0/8"},
			whitelist:      []string{"192.168.1.100", "10.0.0.50"},
			clientIP:       "10.0.0.50",
			expectedStatus: http.StatusOK,
			description:    "Should handle multiple blocked ranges with whitelisted IPs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a Defender instance
			defender := &Defender{
				RawResponder: "block",
				Ranges:       tt.ranges,
				Whitelist:    tt.whitelist,
				responder:    &responders.BlockResponder{},
			}

			// Provision the defender with a mock caddy context
			ctx := caddy.Context{Context: context.Background()}
			defender.log = zap.NewNop()
			err := defender.Provision(ctx)
			require.NoError(t, err, "Failed to provision defender")

			// Create a mock request with the test client IP
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.clientIP + ":12345"

			// Create response recorder
			recorder := httptest.NewRecorder()

			// Create next handler (will be called if request is allowed)
			nextHandler := &mockHandler{}

			// Execute the middleware
			err = defender.ServeHTTP(recorder, req, nextHandler)

			// Check the result
			if tt.expectedStatus == http.StatusOK {
				// Should be no error and next handler should be called
				require.NoError(t, err, "Expected request to be allowed but got error")
				require.Equal(t, http.StatusOK, recorder.Code, "Expected status OK but got %d", recorder.Code)
				require.Equal(t, "OK", recorder.Body.String(), "Expected response from next handler")
			} else {
				// Should be blocked - BlockResponder doesn't return error, just sets status
				require.NoError(t, err, "BlockResponder should not return error")
				require.Equal(t, tt.expectedStatus, recorder.Code, "Expected status %d but got %d", tt.expectedStatus, recorder.Code)
				require.Equal(t, "Access denied", recorder.Body.String(), "Expected 'Access denied' message from BlockResponder")
			}
		})
	}
}

func TestDefenderServeHTTP_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		expectError bool
		description string
	}{
		{
			name:        "Invalid IP format",
			remoteAddr:  "invalid-ip",
			expectError: true,
			description: "Should handle invalid IP format gracefully",
		},
		{
			name:        "Missing port in RemoteAddr",
			remoteAddr:  "192.168.1.1",
			expectError: true,
			description: "Should handle missing port in RemoteAddr",
		},
		{
			name:        "Valid IP with port",
			remoteAddr:  "192.168.1.1:8080",
			expectError: false,
			description: "Should handle valid IP with port correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defender := &Defender{
				RawResponder: "block",
				Ranges:       []string{"192.168.1.0/24"},
				Whitelist:    []string{},
				responder:    &responders.BlockResponder{},
			}

			ctx := caddy.Context{Context: context.Background()}
			defender.log = zap.NewNop()
			err := defender.Provision(ctx)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			recorder := httptest.NewRecorder()
			nextHandler := &mockHandler{}

			err = defender.ServeHTTP(recorder, req, nextHandler)

			if tt.expectError {
				require.Error(t, err, "Expected error for %s", tt.description)
			} else {
				// For valid IP, it should be blocked (since it's in the range and not whitelisted)
				// BlockResponder doesn't return error, just sets status
				require.NoError(t, err, "BlockResponder should not return error")
				require.Equal(t, http.StatusForbidden, recorder.Code, "Expected request to be blocked")
			}
		})
	}
}

func TestDefenderServeHTTP_RobotsFile(t *testing.T) {
	defender := &Defender{
		RawResponder: "block",
		Ranges:       []string{"192.168.1.0/24"},
		ServeIgnore:  true,
		responder:    &responders.BlockResponder{},
	}

	ctx := caddy.Context{Context: context.Background()}
	defender.log = zap.NewNop()
	err := defender.Provision(ctx)
	require.NoError(t, err)

	// Test robots.txt request
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	req.RemoteAddr = "192.168.1.100:8080" // This IP is in blocked range
	recorder := httptest.NewRecorder()
	nextHandler := &mockHandler{}

	err = defender.ServeHTTP(recorder, req, nextHandler)

	// Should serve robots.txt without blocking
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), "User-agent: *")
	require.Contains(t, recorder.Body.String(), "Disallow: /")
}
