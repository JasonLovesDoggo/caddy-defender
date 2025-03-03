package responders

import (
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TarpitResponder returns a custom response.
type TarpitResponder struct {
	Headers      map[string]string `json:"headers"`
	Message      string            `json:"message"`
	Delay        time.Duration     `json:"delay"`
	ResponseCode int               `json:"code"`
}

func (t *TarpitResponder) ServeHTTP(w http.ResponseWriter, _ *http.Request, _ caddyhttp.Handler) error {
	time.Sleep(t.Delay)
	for k, v := range t.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(t.ResponseCode)
	_, err := w.Write([]byte(t.Message))
	return err
}
