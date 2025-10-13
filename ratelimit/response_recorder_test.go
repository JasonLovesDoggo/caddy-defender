package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewResponseRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	if recorder == nil {
		t.Fatal("Expected recorder to be created")
	}

	if recorder.StatusCode != http.StatusOK {
		t.Errorf("Expected default status code to be 200, got %d", recorder.StatusCode)
	}

	if recorder.Written {
		t.Error("Expected Written to be false initially")
	}
}

func TestResponseRecorder_WriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	recorder.WriteHeader(http.StatusNotFound)

	if recorder.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code to be 404, got %d", recorder.StatusCode)
	}

	if !recorder.Written {
		t.Error("Expected Written to be true after WriteHeader")
	}
}

func TestResponseRecorder_WriteHeaderMultipleCalls(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	// First call should set status code
	recorder.WriteHeader(http.StatusNotFound)

	// Second call should be ignored
	recorder.WriteHeader(http.StatusInternalServerError)

	if recorder.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code to remain 404, got %d", recorder.StatusCode)
	}
}

func TestResponseRecorder_Write(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	data := []byte("test data")
	n, err := recorder.Write(data)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}

	if recorder.StatusCode != http.StatusOK {
		t.Errorf("Expected default status code 200, got %d", recorder.StatusCode)
	}

	if !recorder.Written {
		t.Error("Expected Written to be true after Write")
	}

	// Verify data was actually written to underlying writer
	if w.Body.String() != string(data) {
		t.Errorf("Expected body to be '%s', got '%s'", string(data), w.Body.String())
	}
}

func TestResponseRecorder_WriteAfterWriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	recorder.WriteHeader(http.StatusCreated)
	recorder.Write([]byte("content"))

	if recorder.StatusCode != http.StatusCreated {
		t.Errorf("Expected status code to be 201, got %d", recorder.StatusCode)
	}
}

func TestResponseRecorder_Integration(t *testing.T) {
	// Simulate real HTTP handler behavior
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	// Handler writes 404
	recorder.WriteHeader(http.StatusNotFound)
	recorder.Write([]byte("Not Found"))

	if recorder.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code 404, got %d", recorder.StatusCode)
	}

	result := w.Result()
	if result.StatusCode != http.StatusNotFound {
		t.Errorf("Expected underlying writer to have 404, got %d", result.StatusCode)
	}
}

func TestResponseRecorder_DefaultStatusWithoutWriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	// Write without calling WriteHeader explicitly
	recorder.Write([]byte("content"))

	if recorder.StatusCode != http.StatusOK {
		t.Errorf("Expected default status code 200, got %d", recorder.StatusCode)
	}
}

func TestResponseRecorder_Flush(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := NewResponseRecorder(w)

	// Should not panic even if underlying writer doesn't support Flush
	recorder.Flush()
}
