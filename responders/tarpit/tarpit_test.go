package tarpit

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jasonlovesdoggo/caddy-defender/cache"
)

// Helper function to create a new responder
func newTestResponder(content *Content, timeout time.Duration) *Responder {
	return &Responder{
		Config: &Config{
			Content:        content,
			Timeout:        timeout,
			BytesPerSecond: 1024,
			ResponseCode:   200,
		},
	}
}

func TestConfigureContentReader(t *testing.T) {
	t.Run("EmptyContent", func(t *testing.T) {
		content := &Content{}
		responder := newTestResponder(content, time.Second*5)

		err := responder.ConfigureContentReader()
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}
		if _, ok := responder.ContentReader.(TimeoutReader); !ok {
			t.Error("Expected TimeoutReader, but got a different type")
		}
	})

	t.Run("File", func(t *testing.T) {
		// Create a temporary file for testing
		tmpFile, err := os.CreateTemp("", "testfile_")
		if err != nil {
			t.Fatalf("Failed to create temporary file: %v", err)
		}

		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})

		content := &Content{Protocol: "file", Path: tmpFile.Name()}
		responder := newTestResponder(content, time.Second*5)

		// Mocking Validate method to succeed
		responder.ContentReader = FileReader{
			Path: content.Path,
		}
		err = responder.ConfigureContentReader()
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}
		if _, ok := responder.ContentReader.(FileReader); !ok {
			t.Error("Expected FileReader, but got a different type")
		}
	})

	t.Run("HTTP", func(t *testing.T) {
		content := &Content{Protocol: "http", Path: "example.com/data"}
		responder := newTestResponder(content, time.Second*5)

		responder.ContentReader = HTTPReader{
			URL:   "http://example.com/data",
			Cache: cache.New(&cache.Config{Directory: "tarpit"}),
		}
		err := responder.ConfigureContentReader()
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}
		if _, ok := responder.ContentReader.(HTTPReader); !ok {
			t.Error("Expected HTTPReader, but got a different type")
		}
	})

	t.Run("HTTPS", func(t *testing.T) {
		content := &Content{Protocol: "https", Path: "example.com/data"}
		responder := newTestResponder(content, time.Second*5)

		responder.ContentReader = HTTPReader{
			URL:   "https://example.com/data",
			Cache: cache.New(&cache.Config{Directory: "tarpit"}),
		}
		err := responder.ConfigureContentReader()
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}
		if _, ok := responder.ContentReader.(HTTPReader); !ok {
			t.Error("Expected HTTPReader, but got a different type")
		}
	})

	t.Run("UnsupportedProtocol", func(t *testing.T) {
		content := &Content{Protocol: "unsupported", Path: "/data"}
		responder := newTestResponder(content, time.Second*5)

		err := responder.ConfigureContentReader()
		if err == nil || err.Error() != "unsupported tarpit Content protocol 'unsupported'" {
			t.Errorf("Expected error 'unsupported tarpit Content protocol 'unsupported'', but got: %v", err)
		}
	})
}

func TestServeHTTP(t *testing.T) {
	// Mock HTTP request and response writer
	req := &http.Request{}
	rec := &mockResponseWriter{header: http.Header{}}

	t.Run("ValidContent", func(t *testing.T) {
		testFile := "testFileContent"
		// Create a temporary file for testing
		tmpFile, err := os.CreateTemp("", testFile)
		if err != nil {
			t.Fatalf("Failed to create temporary file: %v", err)
		}

		t.Cleanup(func() {
			os.Remove(tmpFile.Name())
		})

		content := &Content{Protocol: "file", Path: testFile}
		responder := newTestResponder(content, time.Second*5)

		// Mock the content reader to return data
		mockReader := &mockReadCloser{data: []byte("Hello, World!")}
		responder.ContentReader = mockReader

		err = responder.ServeHTTP(rec, req, nil)
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}

		// Check if the correct response was written
		if rec.statusCode != http.StatusOK {
			t.Errorf("Expected status code %d, but got %d", http.StatusOK, rec.statusCode)
		}
		if rec.body.String() != "Hello, World!" {
			t.Errorf("Expected body 'Hello, World!', but got: %s", rec.body.String())
		}
	})

	t.Run("ReadError", func(t *testing.T) {
		content := &Content{Protocol: "file", Path: "/tmp/test.txt"}
		responder := newTestResponder(content, time.Second*5)

		// Mock the content reader to return an error
		responder.ContentReader = &mockErrorReader{}

		err := responder.ServeHTTP(rec, req, nil)
		if err != nil {
			t.Error("Did not expect error from ServeHTTP, but got none")
		}

		if rec.statusCode != http.StatusInternalServerError {
			t.Errorf("Expected %d, but got: %d", http.StatusInternalServerError, rec.statusCode)
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		content := &Content{Protocol: "file", Path: "/tmp/test.txt"}
		responder := newTestResponder(content, time.Millisecond*50)

		// Mock a slow reader that causes a timeout
		mockReader := &mockReadCloser{data: []byte("Slow data")}
		responder.ContentReader = mockReader

		err := responder.ServeHTTP(rec, req, nil)
		if err != nil {
			t.Errorf("Expected no error from ServeHTTP, but got: %v", err)
		}
	})
}

// Mock response writer for testing
type mockResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return m.body.Write(b)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

// Implement Flush() method to satisfy the http.Flusher interface
func (m *mockResponseWriter) Flush() {}

// Mock ReadCloser for testing content reading
type mockReadCloser struct {
	data []byte
}

func (m *mockReadCloser) Read() (io.ReadCloser, error) {
	// Return a ReadCloser (simulating file/stream)
	return io.NopCloser(bytes.NewReader(m.data)), nil
}

func (m *mockReadCloser) Validate() error {
	return nil
}
func (m *mockReadCloser) Close() error {
	// Close doesn't do anything in this mock
	return nil
}

// Mock error reader for testing error handling
type mockErrorReader struct{}

func (m *mockErrorReader) Read() (io.ReadCloser, error) {
	return nil, fmt.Errorf("read error")
}

func (m *mockErrorReader) Validate() error {
	return fmt.Errorf("validate error")
}

func (m *mockErrorReader) Close() error {
	return nil
}
