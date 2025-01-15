package responders

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestBlockResponder(t *testing.T) {
	responder := BlockResponder{}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	err := responder.Respond(w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
}

func TestCustomResponder(t *testing.T) {
	message := "Custom message"
	responder := CustomResponder{Message: message}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	err := responder.Respond(w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if body != message {
		t.Errorf("expected body %q, got %q", message, body)
	}
}

func TestGarbageResponder(t *testing.T) {
	responder := GarbageResponder{}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	err := responder.Respond(w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body := w.Body.String()
	if len(body) == 0 {
		t.Errorf("expected non-empty body, got empty body")
	}
}

func TestFileResponder(t *testing.T) {
	// Create a temporary file for testing
	fileContent := "This is a test file."
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(fileContent); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	headers := map[string]string{
		"Content-Type": "text/plain",
		"Content-Encoding": "gzip",
	}
	responder := FileResponder{
		FilePath: tmpFile.Name(),
		Headers: headers,
	}
	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	err = responder.Respond(w, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	for key, value := range headers {
		if resp.Header.Get(key) != value {
			t.Errorf("expected header %q to be %q, got %q", key, value, resp.Header.Get(key))
		}
	}

	body := w.Body.String()
	if !strings.Contains(body, fileContent) {
		t.Errorf("expected body to contain %q, got %q", fileContent, body)
	}
}
