package tarpit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jasonlovesdoggo/caddy-defender/cache"
)

// Helper function to create a test cache instance
func newTestCache() *cache.Cache {
	return cache.New(&cache.Config{Directory: "test_cache"})
}

func TestHTTPReader(t *testing.T) {
	// Create a test cache
	cache := newTestCache()

	t.Run("ValidURL", func(t *testing.T) {
		testValidURL(t, cache)
	})

	t.Run("InvalidURL", func(t *testing.T) {
		testInvalidURL(t, cache)
	})

	t.Run("BadHTTPStatus", func(t *testing.T) {
		testBadHTTPStatus(t, cache)
	})

	t.Run("CacheMissThenSet", func(t *testing.T) {
		testCacheMissThenSet(t, cache)
	})
}

func testValidURL(t *testing.T, cache *cache.Cache) {
	// Create a mock server for the HTTP request
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, world!"))
	}))
	defer mockServer.Close()

	httpReader := HTTPReader{
		URL:   mockServer.URL,
		Cache: cache,
	}

	t.Run("Validate", func(t *testing.T) {
		err := httpReader.Validate()
		if err != nil {
			t.Errorf("Expected no error from Validate, but got: %v", err)
		}
	})

	t.Run("Read", func(t *testing.T) {
		reader, err := httpReader.Read()
		if err != nil {
			t.Errorf("Expected no error from Read, but got: %v", err)
		}
		defer reader.Close()

		data, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("Expected no error reading data, but got: %v", err)
		}

		// Check if the response data is as expected
		expectedData := "Hello, world!"
		if string(data) != expectedData {
			t.Errorf("Expected data %s, but got: %s", expectedData, data)
		}
	})
}

func testInvalidURL(t *testing.T, cache *cache.Cache) {
	// Create an HTTPReader instance with a bad URL
	httpReader := HTTPReader{
		URL:   "http://invalid-url",
		Cache: cache,
	}

	// Test Validate method (should return error)
	t.Run("Validate", func(t *testing.T) {
		err := httpReader.Validate()
		if err == nil {
			t.Errorf("Expected error from Validate with invalid URL, but got none")
		}
	})

	// Test Read method (should return error)
	t.Run("Read", func(t *testing.T) {
		_, err := httpReader.Read()
		if err == nil {
			t.Errorf("Expected error from Read with invalid URL, but got none")
		}
	})
}

func testBadHTTPStatus(t *testing.T, cache *cache.Cache) {
	// Create a mock server that returns a non-OK status
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // Simulate a 404 error
	}))
	defer mockServer.Close()

	httpReader := HTTPReader{
		URL:   mockServer.URL,
		Cache: cache,
	}

	// Test Validate method (should succeed, as the head request will pass)
	t.Run("Validate", func(t *testing.T) {
		err := httpReader.Validate()
		if err != nil {
			t.Errorf("Expected no error from Validate, but got: %v", err)
		}
	})

	// Test Read method (should return an error as the server responds with a 404)
	t.Run("Read", func(t *testing.T) {
		expecterErr := "bad status: 404 Not Found"
		_, err := httpReader.Read()
		if err == nil {
			t.Errorf("Expected error from Read with bad HTTP status, but got none")
		} else if err.Error() != expecterErr {
			t.Errorf("Expected error message '%s', but got: %v", expecterErr, err)
		}
	})
}

func testCacheMissThenSet(t *testing.T, cache *cache.Cache) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello from cache!"))
	}))
	defer mockServer.Close()

	httpReader := HTTPReader{
		URL:   mockServer.URL,
		Cache: cache,
	}

	// Test Read method, first time (cache miss, should hit the HTTP server)
	t.Run("CacheMissThenSet", func(t *testing.T) {
		reader, err := httpReader.Read()
		if err != nil {
			t.Errorf("Expected no error from Read, but got: %v", err)
		}
		defer reader.Close()

		data, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("Expected no error reading data, but got: %v", err)
		}

		// Check if the response data is as expected
		expectedData := "Hello from cache!"
		if string(data) != expectedData {
			t.Errorf("Expected data %s, but got: %s", expectedData, data)
		}
	})

	// Test Read method, second time (cache hit, should read from cache)
	t.Run("CacheHit", func(t *testing.T) {
		reader, err := httpReader.Read()
		if err != nil {
			t.Errorf("Expected no error from Read, but got: %v", err)
		}
		defer reader.Close()

		// Read data from the reader
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("Expected no error reading data, but got: %v", err)
		}

		// Check if the response data is as expected
		expectedData := "Hello from cache!"
		if string(data) != expectedData {
			t.Errorf("Expected data %s, but got: %s", expectedData, data)
		}
	})
}
