package caddydefender

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
)

func TestDefenderBlockedRequestsAccessLogE2E(t *testing.T) {
	logFile := t.TempDir() + "/defender-blocked.log"
	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`{
	admin localhost:2999
	order defender after header
	servers {
		trusted_proxies static 127.0.0.1/32 ::1/128
		client_ip_headers X-Forwarded-For
	}
}

http://localhost:9080 {
	log defender_blocked {
		output file %q
		no_hostname
		format json
	}

	defender block {
		ranges 203.0.113.0/24
		access_log defender_blocked
	}

	respond "allowed"
}`, logFile), "caddyfile")

	allowedReq, err := http.NewRequest(http.MethodGet, "http://localhost:9080/allowed", nil)
	require.NoError(t, err)
	allowedReq.Header.Set("X-Forwarded-For", "198.51.100.10")
	tester.AssertResponse(allowedReq, http.StatusOK, "allowed")

	blockedReq, err := http.NewRequest(http.MethodGet, "http://localhost:9080/blocked", nil)
	require.NoError(t, err)
	blockedReq.Header.Set("X-Forwarded-For", "203.0.113.10")
	tester.AssertResponse(blockedReq, http.StatusForbidden, "Access denied")

	line := readSingleLogLine(t, logFile)

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &entry))
	require.Equal(t, "http.log.access.defender_blocked", entry["logger"])
	require.Equal(t, float64(http.StatusForbidden), entry["status"])
	require.Equal(t, true, entry["defender.blocked"])
	require.Equal(t, "block", entry["defender.action"])
	require.Equal(t, "203.0.113.10", entry["defender.client_ip"])
	require.Equal(t, "ip_range", entry["defender.reason"])
}

func readSingleLogLine(t *testing.T, path string) string {
	t.Helper()

	var data []byte
	require.Eventually(t, func() bool {
		var err error
		data, err = os.ReadFile(path)
		return err == nil && strings.TrimSpace(string(data)) != ""
	}, 2*time.Second, 25*time.Millisecond)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)
	return lines[0]
}
