package cache

import (
	"crypto/md5" // nolint:gosec // Allow use of md5
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// For caching sources on the filesystem.
var cacheParentDir = filepath.Join(os.TempDir(), "caddy-defender")

// Config is used for configuring the cache.
type Config struct {
	Directory string
}

// Cache is a filesystem cache that that allows for caching large files.
type Cache struct {
	Config    *Config
	directory string
}

// New returns a new Cache instance.
func New(c *Config) *Cache {
	return &Cache{
		directory: filepath.Join(cacheParentDir, c.Directory),
	}
}

// Get reads a file from the local cache.
func (c *Cache) Get(key string) (io.ReadCloser, bool, error) {
	cacheKey := generateCacheKey(key)
	file, err := os.Open(filepath.Join(c.directory, cacheKey))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, err
	}

	return file, true, nil
}

// Set writes a file in the local cache.
func (c *Cache) Set(key string, i io.ReadCloser) error {
	var defaultPermissions os.FileMode = 0700

	err := os.MkdirAll(c.directory, defaultPermissions)
	if err != nil {
		return err
	}

	cacheKey := generateCacheKey(key)

	out, err := os.Create(filepath.Join(c.directory, cacheKey))
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, i)
	if err != nil {
		return err
	}

	return i.Close()
}

// generateCacheKey takes a source and returns an md5 checksum as a string for caching files.
func generateCacheKey(path string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(path))) // nolint:gosec // Allow use of md5
}
