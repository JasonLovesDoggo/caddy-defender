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

		err := bl.Add("192.168.1.1/32", "10.0.0.0/8")
		require.NoError(t, err)

		ips := bl.List()
		assert.Len(t, ips, 2)
		assert.Contains(t, ips, "192.168.1.1/32")
		assert.Contains(t, ips, "10.0.0.0/8")
	})

	t.Run("Contains", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		err := bl.Add("192.168.1.1/32")
		require.NoError(t, err)

		assert.True(t, bl.Contains("192.168.1.1/32"))
		assert.False(t, bl.Contains("10.0.0.1/32"))
	})

	t.Run("Remove", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		err := bl.Add("192.168.1.1/32", "10.0.0.0/8")
		require.NoError(t, err)

		removed, err := bl.Remove("192.168.1.1/32")
		require.NoError(t, err)
		assert.True(t, removed)
		assert.False(t, bl.Contains("192.168.1.1/32"))

		removed, err = bl.Remove("nonexistent/32")
		require.NoError(t, err)
		assert.False(t, removed)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		bl := newDynamicBlocklist(testLog)

		done := make(chan bool)

		// Concurrent adds
		for i := 0; i < 10; i++ {
			go func(n int) {
				_ = bl.Add("192.168.1.1/32")
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

func TestDefenderAdminAPIHandlers(t *testing.T) {
	// Create a Defender instance
	defender := &Defender{
		log:              testLog,
		dynamicBlocklist: newDynamicBlocklist(testLog),
		Ranges:           []string{"192.168.1.0/24"},
		RawResponder:     "block",
	}
	defender.ipChecker = ip.NewIPChecker(defender.Ranges, []string{}, testLog)

	// Create DefenderAdmin and register the Defender instance
	admin := &DefenderAdmin{
		log:       testLog,
		defenders: make(map[string]*Defender),
	}
	admin.RegisterDefender("test", defender)

	t.Run("GET /defender/blocklist - empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/blocklist", nil)
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, float64(0), response["total"])
		sources := response["sources"].(map[string]interface{})
		assert.Equal(t, float64(0), sources["dynamic"])
		assert.Equal(t, float64(0), sources["file"])
	})

	t.Run("POST /defender/blocklist - add IPs", func(t *testing.T) {
		body := bytes.NewBufferString(`{"ips": ["192.168.2.1/32", "10.0.0.0/8"]}`)
		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, float64(2), response["count"])
		added := response["added"].([]interface{})
		assert.Len(t, added, 2)
	})

	t.Run("GET /defender/blocklist - with IPs", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/blocklist", nil)
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, float64(2), response["total"])
		sources := response["sources"].(map[string]interface{})
		assert.Equal(t, float64(2), sources["dynamic"])

		ips := response["ips"].([]interface{})
		assert.Len(t, ips, 2)
	})

	t.Run("POST /defender/blocklist - invalid CIDR", func(t *testing.T) {
		body := bytes.NewBufferString(`{"ips": ["192.168.1.1"]}`)
		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.Error(t, err)
	})

	t.Run("POST /defender/blocklist - empty IPs", func(t *testing.T) {
		body := bytes.NewBufferString(`{"ips": []}`)
		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.Error(t, err)
	})

	t.Run("DELETE /defender/blocklist/{ip}", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/defender/blocklist/192.168.2.1/32", nil)
		w := httptest.NewRecorder()

		err := admin.handleBlocklistItem(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "192.168.2.1/32", response["removed"])
	})

	t.Run("DELETE /defender/blocklist/{ip} - not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/defender/blocklist/nonexistent/32", nil)
		w := httptest.NewRecorder()

		err := admin.handleBlocklistItem(w, req)
		require.Error(t, err)
	})

	t.Run("GET /defender/stats", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/stats", nil)
		w := httptest.NewRecorder()

		err := admin.handleStats(w, req)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "block", response["responder"])
		counts := response["counts"].(map[string]interface{})
		assert.Equal(t, float64(1), counts["configured_ranges"])
	})

	t.Run("ConcurrentAPIAccess", func(t *testing.T) {
		done := make(chan bool)

		// Concurrent POST requests
		for i := 0; i < 5; i++ {
			go func() {
				body := bytes.NewBufferString(`{"ips": ["172.16.0.0/12"]}`)
				req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", body)
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				_ = admin.handleBlocklist(w, req)
				done <- true
			}()
		}

		// Concurrent GET requests
		for i := 0; i < 5; i++ {
			go func() {
				req := httptest.NewRequest(http.MethodGet, "/defender/blocklist", nil)
				w := httptest.NewRecorder()
				_ = admin.handleBlocklist(w, req)
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("Routes method", func(t *testing.T) {
		routes := admin.Routes()
		assert.Len(t, routes, 3)
		assert.Equal(t, "/defender/blocklist", routes[0].Pattern)
		assert.Equal(t, "/defender/blocklist/*", routes[1].Pattern)
		assert.Equal(t, "/defender/stats", routes[2].Pattern)
	})
}

func TestDefenderAdminNoDefender(t *testing.T) {
	// Create DefenderAdmin with no registered Defender instances
	admin := &DefenderAdmin{
		log:       testLog,
		defenders: make(map[string]*Defender),
	}

	t.Run("GET /defender/blocklist - no defender", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/blocklist", nil)
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.Error(t, err)
	})

	t.Run("POST /defender/blocklist - no defender", func(t *testing.T) {
		body := bytes.NewBufferString(`{"ips": ["192.168.1.1/32"]}`)
		req := httptest.NewRequest(http.MethodPost, "/defender/blocklist", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		err := admin.handleBlocklist(w, req)
		require.Error(t, err)
	})

	t.Run("GET /defender/stats - no defender", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/defender/stats", nil)
		w := httptest.NewRecorder()

		err := admin.handleStats(w, req)
		require.Error(t, err)
	})
}
