package caddydefender

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jasonlovesdoggo/caddy-defender/ranges/data"
	"github.com/jasonlovesdoggo/caddy-defender/responders"
)

func TestDefenderMiddleware_BlockResponder(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{"203.0.113.0/24"},
		responder:        &responders.BlockResponder{},
		log:              caddy.Log(),
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := middleware.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

func TestDefenderMiddleware_GarbageResponder(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{"203.0.113.0/24"},
		responder:        &responders.GarbageResponder{},
		log:              caddy.Log(),
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := middleware.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestDefenderMiddleware_CustomResponder(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{"203.0.113.0/24"},
		responder:        &responders.CustomResponder{Message: "Custom response"},
		log:              caddy.Log(),
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := middleware.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if body != "Custom response" {
		t.Errorf("expected body %q, got %q", "Custom response", body)
	}
}

func TestDefenderMiddleware_PredefinedRanges(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{"openai"},
		responder:        &responders.BlockResponder{},
		log:              caddy.Log(),
	}

	for _, ipRange := range data.IPRanges["openai"] {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.RemoteAddr = ipRange + ":12345"
		w := httptest.NewRecorder()

		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})

		err := middleware.ServeHTTP(w, req, next)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		resp := w.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
		}
	}
}

func TestDefenderMiddleware_MultipleRanges(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{"203.0.113.0/24", "198.51.100.0/24"},
		responder:        &responders.BlockResponder{},
		log:              caddy.Log(),
	}

	testCases := []struct {
		ip       string
		expected int
	}{
		{"203.0.113.1:12345", http.StatusForbidden},
		{"198.51.100.1:12345", http.StatusForbidden},
		{"192.0.2.1:12345", http.StatusOK},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", "http://example.com/foo", nil)
		req.RemoteAddr = tc.ip
		w := httptest.NewRecorder()

		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})

		err := middleware.ServeHTTP(w, req, next)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		resp := w.Result()
		if resp.StatusCode != tc.expected {
			t.Errorf("expected status %d, got %d", tc.expected, resp.StatusCode)
		}
	}
}

func TestDefenderMiddleware_EmptyRanges(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{},
		responder:        &responders.BlockResponder{},
		log:              caddy.Log(),
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := middleware.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestDefenderMiddleware_InvalidIP(t *testing.T) {
	middleware := DefenderMiddleware{
		AdditionalRanges: []string{"203.0.113.0/24"},
		responder:        &responders.BlockResponder{},
		log:              caddy.Log(),
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.RemoteAddr = "invalid-ip:12345"
	w := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	err := middleware.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
}
