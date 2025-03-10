package tarpit

import (
	"fmt"
	"io"
	"net/http"

	"github.com/jasonlovesdoggo/caddy-defender/cache"
)

// HTTPReader implements the ContentReader interface and reads remote files over http.
type HTTPReader struct {
	Cache *cache.Cache
	URL   string
}

// Read opens a file for streaming.
func (h HTTPReader) Read() (io.ReadCloser, error) {
	reader, ok, err := h.Cache.Get(h.URL)
	if err != nil {
		return nil, err
	}

	// Return if in the cache
	if ok {
		return reader, nil
	}

	// If not in cache, set it
	if !ok {
		// Get the data
		resp, err := http.Get(h.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		// Check server response
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("bad status: %s", resp.Status)
		}

		// If not in cache, set it, then return reader
		err = h.Cache.Set(h.URL, resp.Body)
		if err != nil {
			return nil, err
		}
	}

	// After setting the cache, try again
	reader, _, err = h.Cache.Get(h.URL)
	if err != nil {
		return nil, err
	}

	return reader, err
}

// Validate ensures the remote file is accessible.
func (h HTTPReader) Validate() error {
	resp, err := http.Head(h.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
