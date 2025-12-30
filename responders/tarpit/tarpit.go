package tarpit

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"pkg.jsn.cam/caddy-defender/cache"
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
	Headers         map[string]string `json:"headers"`
	Content         Content
	Timeout         time.Duration `json:"timeout"`
	HeaderPerSecond int           `json:"header_per_second"`
	BytesPerSecond  int           `json:"bytes_per_second"`
	ResponseCode    int           `json:"code"`
}

// ConfigureContentReader checks the content protocol configuration
// and configures the appropriate content reader for the tarpit responder.
func (r *Responder) ConfigureContentReader() error {
	err := r.Validate()
	if err != nil {
		return err
	}
	if r.Config.Content.Protocol == "" && r.Config.Content.Path != "" {
		return fmt.Errorf("missing tarpit Content protocol")
	}
	switch r.Config.Content.Protocol {
	// If no content to provide, we'll just hold the connection open
	case "":
		r.ContentReader = TimeoutReader{}
	case "file":
		r.ContentReader = FileReader{
			Path: r.Config.Content.Path,
		}
		err := r.ContentReader.Validate()
		if err != nil {
			return err
		}
	case "http", "https":
		tarCache := cache.New(&cache.Config{
			Directory: "tarpit",
		})
		r.ContentReader = HTTPReader{
			URL:   r.Config.Content.Protocol + "://" + r.Config.Content.Path,
			Cache: tarCache,
		}
		err := r.ContentReader.Validate()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported tarpit Content protocol '%s'", r.Config.Content.Protocol)
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
		_, err = w.Write(buffer[:n])
		if err != nil {
			return err
		}
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
			// Stop if client disconnects to prevent panic
			if req.Context().Err() != nil {
				break
			}

			n, err := reader.Read(chunk)
			if err == io.EOF {
				// Graceful exit as we've reached the end of the content
				return nil
			} else if err != nil {
				return err
			}
			if n > 0 {
				_, err = w.Write(chunk[:n])
				if err != nil {
					return err
				}
				w.(http.Flusher).Flush()
			}
		case <-timeout:
			// Forcefully close response after timeout
			return nil
		}
	}
}

func (r *Responder) Validate() error {
	if r.Config.Timeout <= 0 {
		return errors.New("tarpit timeout must be greater than 0")
	}
	if r.Config.BytesPerSecond <= 10 {
		return errors.New("tarpit bytes_per_second must be greater than 10")
	}
	return nil
}
