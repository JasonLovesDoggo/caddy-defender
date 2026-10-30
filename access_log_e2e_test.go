package caddydefender

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
)

func TestDefenderBlockedRequestsAccessLogE2E(t *testing.T) {
	logAddr, logLines, logErrs := startAccessLogServer(t)
	tester := caddytest.NewTester(t)
	defer tester.InitServer(`{
	admin localhost:2999
}`, "caddyfile")

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
		output net %q {
			dial_timeout 1s
		}
		no_hostname
		format json
	}

	defender block {
		ranges 203.0.113.0/24
		access_log defender_blocked
	}

	respond "allowed"
}`, logAddr), "caddyfile")

	allowedReq, err := http.NewRequest(http.MethodGet, "http://localhost:9080/allowed", nil)
	require.NoError(t, err)
	allowedReq.Header.Set("X-Forwarded-For", "198.51.100.10")
	allowedResp, _ := tester.AssertResponse(allowedReq, http.StatusOK, "allowed")
	require.NoError(t, allowedResp.Body.Close())

	blockedReq, err := http.NewRequest(http.MethodGet, "http://localhost:9080/blocked", nil)
	require.NoError(t, err)
	blockedReq.Header.Set("X-Forwarded-For", "203.0.113.10")
	blockedResp, _ := tester.AssertResponse(blockedReq, http.StatusForbidden, "Access denied")
	require.NoError(t, blockedResp.Body.Close())

	line := readLogLine(t, logLines, logErrs)

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &entry))
	require.Equal(t, "http.log.access.defender_blocked", entry["logger"])
	require.Equal(t, float64(http.StatusForbidden), entry["status"])
	require.Equal(t, true, entry["defender.blocked"])
	require.Equal(t, "block", entry["defender.action"])
	require.Equal(t, "203.0.113.10", entry["defender.client_ip"])
	require.Equal(t, "ip_range", entry["defender.reason"])
}

func startAccessLogServer(t *testing.T) (string, <-chan string, <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
	})

	lines := make(chan string, 1)
	errs := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()

		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			errs <- err
			return
		}
		lines <- line
	}()

	return "tcp/" + listener.Addr().String(), lines, errs
}

func readLogLine(t *testing.T, lines <-chan string, errs <-chan error) string {
	t.Helper()

	select {
	case line := <-lines:
		return strings.TrimSpace(line)
	case err := <-errs:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for access log entry")
	}
	return ""
}
