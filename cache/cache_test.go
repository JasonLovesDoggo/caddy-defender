package cache

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Helper function to create a temporary cache instance for testing
func newTestCache() *Cache {
	return New(&Config{Directory: "test_cache"})
}

func TestNew(t *testing.T) {
	t.Run("Ensure cache directory configured", func(t *testing.T) {
		cacheDir := "test"
		expected := filepath.Join(cacheParentDir, cacheDir)
		config := &Config{
			Directory: cacheDir,
		}

		cache := New(config)
		if cache.directory != expected {
			t.Errorf("expected %s, but got %s", expected, cache.directory)
		}
	})
}

func TestGet(t *testing.T) {
	t.Run("Ensure cache hit", func(t *testing.T) {
		cache := newTestCache()
		key := "test_key"
		data := []byte("Hello, Cache!")

		t.Cleanup(func() {
			os.RemoveAll(cache.directory)
		})

		// Create an io.Reader from the data
		r := io.NopCloser(bytes.NewReader(data))

		err := cache.Set(key, r)
		if err != nil {
			t.Errorf("Expected no error from Set, but got: %v", err)
		}

		// Test Get function
		file, found, err := cache.Get(key)
		if err != nil {
			t.Errorf("Expected no error from Get, but got: %v", err)
		}
		if !found {
			t.Error("Expected file to be found in cache, but it was not")
		}

		// Read data from the file
		readData, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("Expected no error reading file, but got: %v", err)
		}

		// Check that the data matches what was written
		if string(readData) != string(data) {
			t.Fatalf("Expected data %s, but got: %s", data, readData)
		}
	})

	t.Run("Ensure cache miss", func(t *testing.T) {
		cache := newTestCache()
		key := "nonexistent_key"

		// Test Get function with a key that does not exist
		file, found, err := cache.Get(key)
		if err != nil {
			t.Errorf("Expected no error from Get, but got: %v", err)
		}
		if found {
			t.Error("Expected file not to be found in cache, but it was")
		}
		if file != nil {
			t.Error("Expected file to be nil for nonexistent cache entry")
		}
	})
}

func TestSet(t *testing.T) {
	t.Run("Ensure data is written to cache", func(t *testing.T) {
		cache := newTestCache()
		key := "some_key"
		data := []byte("") // Empty data

		t.Cleanup(func() {
			os.RemoveAll(cache.directory)
		})

		// Create an io.Reader from the empty data
		r := io.NopCloser(bytes.NewReader(data))

		// Test Set function with empty data
		err := cache.Set(key, r)
		if err != nil {
			t.Errorf("Expected no error from Set, but got: %v", err)
		}

		file, found, err := cache.Get(key)
		if err != nil {
			t.Errorf("Expected no error from Get, but got: %v", err)
		}
		if !found {
			t.Error("Expected file to be found in cache, but it was not")
		}

		// Read data from the file
		readData, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("Expected no error reading file, but got: %v", err)
		}

		// Check that the data matches the empty data
		if string(readData) != string(data) {
			t.Fatalf("Expected data %s, but got: %s", data, readData)
		}
	})
}

func TestGenerateCacheKey(t *testing.T) {
	path := "test_path"
	expectedKey := "5da6ae5928d4a1ce395878ae9c7ea1f6" // MD5 hash of "test_path"
	cacheKey := generateCacheKey(path)
	if cacheKey != expectedKey {
		t.Errorf("Expected cache key %s, but got: %s", expectedKey, cacheKey)
	}
}
