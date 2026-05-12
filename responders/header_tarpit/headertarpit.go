package header_tarpit

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Config holds the tarpit responder's configuration.
type Config struct {
	Headers      map[string]string `json:"headers"`
	Timeout      time.Duration     `json:"timeout"`
	DelaySecond  int               `json:"header_per_second"`
	ResponseCode int               `json:"code"`
}

// Responder returns a custom response.
type Responder struct {
	Config *Config
}

func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request, _ caddyhttp.Handler) error {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return errors.New("webserver doesn't support hijacking")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}

	defer conn.Close()

	h := fmt.Sprintf("HTTP/1.1 %d %s\n", r.Config.ResponseCode, http.StatusText(r.Config.ResponseCode))
	bufrw.WriteString(h)
	bufrw.Flush()

	// Write any prelude headers
	for key, value := range r.Config.Headers {
		bufrw.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	bufrw.Flush()

	// Write successive headers per delay
	ticker := time.NewTicker(time.Duration(r.Config.DelaySecond) * time.Second)
	defer ticker.Stop()

	timeout := time.After(r.Config.Timeout)

	for {
		select {
		case <-ticker.C:
			s := fmt.Sprintf("X-%016x: %016x\n", rand.Uint64(), rand.Uint64())
			bufrw.WriteString(s)
			bufrw.Flush()
		case <-timeout:
			return nil
		}
	}
}

func (r *Responder) Validate() error {
	if r.Config.Timeout <= 0 {
		return errors.New("header_tarpit timeout must be greater than 0")
	}
	if r.Config.DelaySecond <= 0 {
		return errors.New("header_tarpit header_per_second must be greater than 0")
	}
	return nil
}
