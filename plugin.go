package caddydefender

import (
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
	httpcaddyfile.RegisterDirectiveOrder("defender", "before", "respond")

}

// Defender implements an HTTP middleware that enforces IP-based rules to protect your site from AIs/Scrapers.
// It allows you to block or manipulate requests based on the client's IP address by specifying IP ranges to block
// or using predefined ranges for popular services like AWS, GCP, OpenAI, and GitHub Copilot.
//
// The middleware supports multiple responder types, including blocking requests, returning garbage data, or
// sending custom messages.
type Defender struct {
	// Ranges specifies additional IP ranges provided by the user to block or manipulate.
	// These ranges are in CIDR notation (e.g., "192.168.1.0/24") and are applied alongside predefined ranges.
	// This field is optional.
	Ranges []string `json:"ranges,omitempty"`

	// RangesFile specifies the path to a file containing IP ranges (one per line) to block or manipulate.
	// The file can include CIDR ranges or predefined range keys (e.g., "aws", "gcloud").
	// This field is optional.
	RangesFile string `json:"ranges_file,omitempty"`

	// Message specifies a custom message to return to the client when using the "custom" responder.
	// This field is optional and only used when the responder type is set to "custom".
	Message string `json:"message,omitempty"`

	// RawResponder is an internal field that represents the responder type specified in the configuration.
	// Supported values are "block", "garbage", and "custom".
	// This field is optional and is used during configuration unmarshaling.
	RawResponder string `json:"raw_responder,omitempty"`

	// responder is the internal responder interface used to handle requests that match the specified IP ranges.
	// It is set based on the value of RawResponder during configuration validation.
	responder Responder

	// log is the logger used for logging debug and error messages within the middleware.
	log *zap.Logger
}

// Provision sets up the middleware and logger.
func (m *Defender) Provision(ctx caddy.Context) error {

	m.log = ctx.Logger(m)
	m.log.Debug("Provisioning Defender", zap.Strings("ranges", m.Ranges), zap.String("ranges_file", m.RangesFile))
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
	defender := new(Defender)
	err := defender.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return defender, nil
}

var (
	_ caddy.Provisioner           = (*Defender)(nil)
	_ caddy.Validator             = (*Defender)(nil)
	_ caddyhttp.MiddlewareHandler = (*Defender)(nil)
	_ caddyfile.Unmarshaler       = (*Defender)(nil)
)
