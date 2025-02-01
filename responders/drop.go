package responders

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// DropResponder drops the connection.
type DropResponder struct{}

func (d *DropResponder) ServeHTTP(w http.ResponseWriter, _ *http.Request, _ caddyhttp.Handler) error {
	panic(http.ErrAbortHandler)
}
