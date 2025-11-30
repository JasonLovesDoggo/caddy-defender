package responders

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// CustomResponder returns a custom response with configurable message and status code.
type CustomResponder struct {
	// Message is the custom response message to return to clients.
	// Required.
	Message string `json:"message"`

	// StatusCode is the HTTP status code to return.
	// Optional. Default: 200 (OK)
	StatusCode int `json:"status_code,omitempty"`
}

func (c CustomResponder) ServeHTTP(w http.ResponseWriter, _ *http.Request, _ caddyhttp.Handler) error {
	// Use default status code if not specified
	statusCode := c.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(c.Message))
	return err
}
