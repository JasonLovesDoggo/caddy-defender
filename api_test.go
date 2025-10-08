package caddydefender

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"pkg.jsn.cam/caddy-defender/matchers/ip"
)

var testLog = zap.NewNop()

func TestDynamicBlocklist(t *testing.T) {
	t.Run("Add and List", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		bl.Add("192.168.1.1/32", "10.0.0.0/8")

		ips := bl.List()
		assert.Len(t, ips, 2)
		assert.Contains(t, ips, "192.168.1.1/32")
		assert.Contains(t, ips, "10.0.0.0/8")
	})

	t.Run("Contains", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		bl.Add("192.168.1.1/32")

		assert.True(t, bl.Contains("192.168.1.1/32"))
		assert.False(t, bl.Contains("10.0.0.1/32"))
	})

	t.Run("Remove", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		bl.Add("192.168.1.1/32", "10.0.0.0/8")

		removed := bl.Remove("192.168.1.1/32")
		assert.True(t, removed)
		assert.False(t, bl.Contains("192.168.1.1/32"))

		removed = bl.Remove("nonexistent/32")
		assert.False(t, removed)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		done := make(chan bool)

		// Concurrent adds
		for i := 0; i < 10; i++ {
			go func(n int) {
				bl.Add("192.168.1.1/32")
				done <- true
			}(i)
		}

		// Concurrent reads
		for i := 0; i < 10; i++ {
			go func() {
				_ = bl.List()
				_ = bl.Contains("192.168.1.1/32")
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 20; i++ {
			<-done
		}

		// Should have the IP
		assert.True(t, bl.Contains("192.168.1.1/32"))
	})
}

func TestAPIHandlers(t *testing.T) {
	defender := &Defender{
		log:              testLog,
		dynamicBlocklist: newDynamicBlocklist(testLog),
		Ranges:           []string{"192.168.1.0/24"}, // Use real CIDR for test
		RawResponder:     "block",
	}
	// Initialize IPChecker for tests
	defender.ipChecker = ip.NewIPChecker(defender.Ranges, []string{}, testLog)

	t.Run("GET /defender/blocklist - empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/blocklist", nil)
		w := httptest.NewRecorder()

		err := defender.handleBlocklist(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, float64(0), response["count"])
		assert.Empty(t, response["ips"])
	})

	t.Run("POST /defender/blocklist - add IPs", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"ips": []string{"192.168.1.100/32", "10.0.0.0/8"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", bytes.NewReader(body))
		w := httptest.NewRecorder()

		err := defender.handleBlocklist(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, float64(2), response["count"])
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("POST /defender/blocklist - invalid CIDR", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"ips": []string{"192.168.1.100"}, // Missing /32
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", bytes.NewReader(body))
		w := httptest.NewRecorder()

		err := defender.handleBlocklist(w, req)
		assert.Error(t, err)
	})

	t.Run("POST /defender/blocklist - no IPs", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"ips": []string{},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", bytes.NewReader(body))
		w := httptest.NewRecorder()

		err := defender.handleBlocklist(w, req)
		assert.Error(t, err)
	})

	t.Run("GET /defender/blocklist - with IPs", func(t *testing.T) {
		defender.dynamicBlocklist.Add("192.168.1.1/32", "10.0.0.0/8")

		req := httptest.NewRequest(http.MethodGet, "/defender/blocklist", nil)
		w := httptest.NewRecorder()

		err := defender.handleBlocklist(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Greater(t, response["count"], float64(0))
		ips := response["ips"].([]interface{})
		assert.NotEmpty(t, ips)
	})

	t.Run("DELETE /defender/blocklist/{ip}", func(t *testing.T) {
		defender.dynamicBlocklist.Add("192.168.1.1/32")

		req := httptest.NewRequest(http.MethodDelete, "/defender/blocklist/192.168.1.1/32", nil)
		req.URL.Path = "/defender/blocklist/192.168.1.1/32"
		w := httptest.NewRecorder()

		err := defender.handleBlocklistItem(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "192.168.1.1/32", response["removed"])
		assert.False(t, defender.dynamicBlocklist.Contains("192.168.1.1/32"))
	})

	t.Run("DELETE /defender/blocklist/{ip} - not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/defender/blocklist/nonexistent/32", nil)
		req.URL.Path = "/defender/blocklist/nonexistent/32"
		w := httptest.NewRecorder()

		err := defender.handleBlocklistItem(w, req)
		assert.Error(t, err)
	})

	t.Run("GET /defender/stats", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/stats", nil)
		w := httptest.NewRecorder()

		err := defender.handleStats(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Contains(t, response, "configured_ranges")
		assert.Contains(t, response, "counts")
		assert.Contains(t, response, "responder")
		assert.Equal(t, "block", response["responder"])
	})

	t.Run("Invalid method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/defender/blocklist", nil)
		w := httptest.NewRecorder()

		err := defender.handleBlocklist(w, req)
		assert.Error(t, err)
	})
}

func TestRoutes(t *testing.T) {
	defender := &Defender{
		log:              testLog,
		dynamicBlocklist: newDynamicBlocklist(testLog),
	}

	routes := defender.Routes()

	assert.Len(t, routes, 3)

	patterns := []string{
		"/defender/blocklist",
		"/defender/blocklist/*",
		"/defender/stats",
	}

	for i, route := range routes {
		assert.Equal(t, patterns[i], route.Pattern)
		assert.NotNil(t, route.Handler)
	}
}
