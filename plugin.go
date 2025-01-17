package caddydefender

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	// Register the module with Caddy
	caddy.RegisterModule(Defender{})
	httpcaddyfile.RegisterHandlerDirective("defender", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("defender", "before", "request_header")

}

// Defender implements an HTTP middleware that enforces IP-based rules to protect your site from AIs/Scrapers.
type Defender struct {
	// IP ranges specified by the user to block. (optional)
	Ranges []string `json:"ranges,omitempty"`

	// specifies the path to a file containing IP ranges (one per line) to act on. (optional)
	RangesFile string `json:"ranges_file,omitempty"`

	// Custom message to return to the client when using "custom" middleware (optional)
	Message string `json:"message,omitempty"`

	// Internal field representing the actual responder interface
	RawResponder string `json:"raw_responder,omitempty"  caddy:"namespace=http.handlers.defender inline_key=responder"`

	//  the type of Responder to use. (e.g. "block", "custom", etc.)
	Responder Responder `json:"-"`

	// Logger
	log *zap.Logger
}

// Provision sets up the middleware and logger.
func (m *Defender) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger(m)
	// print everythibng in m
	fmt.Println(m.Message)
	fmt.Println(m.RawResponder)
	fmt.Println(m.Ranges)
	fmt.Println(m.RangesFile)

	// Load ranges from file if specified
	if m.RangesFile != "" {
		m.log.Info("Loading ranges from file", zap.String("file", m.RangesFile))
		ranges, err := loadRangesFromFile(m.RangesFile)
		if err != nil {
			m.log.Error("Failed to load ranges from file", zap.Error(err))
			return fmt.Errorf("failed to load ranges from file: %v", err)
		}
		m.Ranges = ranges
		m.log.Info("Ranges loaded successfully", zap.Strings("ranges", m.Ranges))
	} else {
		m.log.Info("No ranges file specified, using default ranges")
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
	return &m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Defender)(nil)
	_ caddyhttp.MiddlewareHandler = (*Defender)(nil)
	_ caddyfile.Unmarshaler       = (*Defender)(nil)
	_ caddy.Validator             = (*Defender)(nil)
	_ caddy.Module                = (*Defender)(nil)
)
