package caddydefender

import (
	"bufio"
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net"
	"os"
)

func init() {
	// Register the module with Caddy
	caddy.RegisterModule(Defender{})
	httpcaddyfile.RegisterHandlerDirective("defender", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("defender", "before", "basicauth")

}

// Defender implements an HTTP middleware that enforces IP-based rules to protect your site from AIs/Scrapers.
type Defender struct {
	// Additional IP ranges specified by the user
	AdditionalRanges []string `json:"additional_ranges,omitempty"`

	// specifies the path to a file containing IP ranges (one per line) to act on. (optional)
	RangesFile string `json:"ranges_file,omitempty"`

	// Use concrete responder type for JSON
	ResponderRaw json.RawMessage `json:"responder,omitempty"`

	// Custom message to return to the client when using "custom" middleware (optional)
	Message string `json:"message,omitempty"`

	// Internal field for the actual responder interface
	responder Responder

	// Logger
	log *zap.Logger
}

// Provision sets up the middleware and logger.
func (m *Defender) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger(m)

	// Load ranges from the specified text filez
	if m.RangesFile != "" {
		file, err := os.Open(m.RangesFile)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			_, _, err := net.ParseCIDR(line)
			if err != nil {
				return err
			}
		}

		if err := scanner.Err(); err != nil {
			return err
		}
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (Defender) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.defender",
		New: func() caddy.Module { return new(Defender) },
	}
}

// parseCaddyfile unmarshals tokens from h into a new Defender.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Defender
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner = (*Defender)(nil)
	//_ caddyhttp.MiddlewareHandler = (*Defender)(nil)
	_ caddyfile.Unmarshaler = (*Defender)(nil)
)
