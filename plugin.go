package caddydefender

import (
	"bufio"
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net"
	"os"
)

func init() {
	// Register the module with Caddy
	caddy.RegisterModule(DefenderMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("defender", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("defender", "before", "basicauth")

}

// DefenderMiddleware implements an HTTP middleware that enforces IP-based rules.
type DefenderMiddleware struct {
	// Additional IP ranges specified by the user
	AdditionalRanges []string `json:"additional_ranges,omitempty"`
	// Responder backend to use
	// Use concrete responder type for JSON
	ResponderRaw json.RawMessage `json:"responder,omitempty"`
	// Internal field for the actual responder interface
	responder       Responder       `json:"-"`
	ResponderConfig json.RawMessage `json:"responder_config,omitempty"`

	// RangesFile specifies the path to a file containing IP ranges
	RangesFile string `json:"ranges_file,omitempty"`

	// Logger
	log *zap.Logger
}

// Provision sets up the middleware and logger.
func (m *DefenderMiddleware) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger(m)

	// Load ranges from the specified text file
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
func (DefenderMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.defender",
		New: func() caddy.Module { return new(DefenderMiddleware) },
	}
}

// parseCaddyfile parses the Caddyfile directive.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m DefenderMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}
