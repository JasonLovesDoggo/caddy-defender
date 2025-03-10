package tarpit

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jasonlovesdoggo/caddy-defender/cache"
)

// ContentReader is an interface for fetching data from different data Contents to supply data to the tarpit.
type ContentReader interface {
	Read() (io.ReadCloser, error)
	Validate() error
}

// Content holds the protocol and path for a data Content for the tarpit such as file://file.txt.
type Content struct {
	Protocol string
	Path     string
}

// Config holds the tarpit responder's configuration.
type Config struct {
	Headers        map[string]string `json:"headers"`
	Content        *Content
	Timeout        time.Duration `json:"timeout"`
	BytesPerSecond int           `json:"bytes_per_second"` // todo: make this value vary.
	ResponseCode   int           `json:"code"`
}

// ConfigureContentReader checks the content protocol configuration
// and configures the appropriate content reader for the tarpit responder.
func (r *Responder) ConfigureContentReader() error {
	switch r.Config.Content.Protocol {
	// If no content to provide, we'll just hold the connection open
	case "":
		r.ContentReader = TimeoutReader{} // todo: add a text:// protocol
	case "file":
		r.ContentReader = FileReader{
			Path: r.Config.Content.Path,
		}
		err := r.ContentReader.Validate()
		if err != nil {
			return err
		}
	case "http", "https":
		tCache := cache.New(&cache.Config{
			Directory: "tarpit",
		})
		r.ContentReader = HTTPReader{
			URL:   r.Config.Content.Protocol + "://" + r.Config.Content.Path,
			Cache: tCache,
		}
		err := r.ContentReader.Validate()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported tarpit Content protocol '%s'",
			r.Config.Content.Protocol) // todo: return list of supported protocols.
	}

	return nil
}

// Responder returns a custom response.
type Responder struct {
	Config        *Config
	ContentReader ContentReader
}

func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request, _ caddyhttp.Handler) error {
	// Open Content data stream
	reader, err := r.ContentReader.Read()
	if err != nil {
		http.Error(w, "Failed to read Content", http.StatusInternalServerError)
		return nil
	}
	defer reader.Close()

	// Read the first 512 bytes to detect content type
	buffer := make([]byte, 512)
	n, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		http.Error(w, "Error reading Content", http.StatusInternalServerError)
		return nil
	}

	// Set headers
	for key, value := range r.Config.Headers {
		w.Header().Set(key, value)
	}
	// Auto-detect content type
	w.Header().Set("Content-Type", http.DetectContentType(buffer[:n]))
	w.WriteHeader(r.Config.ResponseCode)

	// Write the first chunk before starting the ticker
	if n > 0 {
		_, _ = w.Write(buffer[:n])
		w.(http.Flusher).Flush()
	}

	chunk := make([]byte, r.Config.BytesPerSecond/10)

	// Write data every 100ms
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()

	timeout := time.After(r.Config.Timeout)

	for {
		select {
		case <-ticker.C:
			n, ReadErr := reader.Read(chunk)
			if ReadErr == io.EOF {
				// Graceful exit as we've reached the end of the file
				return nil
			} else if ReadErr != nil {
				return ReadErr
			}
			if n > 0 {
				_, ReadErr = w.Write(chunk[:n])
				if ReadErr != nil {
					return ReadErr
				}
				w.(http.Flusher).Flush()
			}
		case <-timeout:
			// Forcefully close response after duration expires
			return nil
		}
	}
}
