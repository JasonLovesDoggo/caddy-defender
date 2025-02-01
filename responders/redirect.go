package responders

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// RedirectResponder redirects a request with a 308 permanent redirect response.
type RedirectResponder struct {
	URL string
}

func (r *RedirectResponder) ServeHTTP(w http.ResponseWriter, req *http.Request, _ caddyhttp.Handler) error {
	http.Redirect(w, req, r.URL, http.StatusPermanentRedirect)
	return nil
}
