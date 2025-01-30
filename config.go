package caddydefender

import (
	"encoding/json"
	"fmt"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jasonlovesdoggo/caddy-defender/matchers/whitelist"
	"github.com/jasonlovesdoggo/caddy-defender/ranges/data"
	"github.com/jasonlovesdoggo/caddy-defender/responders"
	"net"
	"reflect"
	"slices"
)

var responderTypes = []string{"block", "garbage", "custom", "ratelimit"}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	defender <responder> {
//		# IP ranges to block
//		ranges
//		# Whitelisted IP addresses to allow to bypass ranges (optional)
//		whitelist
//	    # Custom message to return to the client when using "custom" middleware (optional)
//	    message
//	    # Serve robots.txt banning everything (optional)
//	    serve_ignore (no arguments)
//	}
func (m *Defender) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// Get the responder type
	if !d.NextArg() {
		return d.Errf("missing responder type")
	}
	// validate responder type
	if !slices.Contains(responderTypes, d.Val()) {
		return d.Errf("invalid responder type: %s", d.Val())
	} else {
		m.RawResponder = d.Val()
	}

	// Parse the block if it exists
	var ranges []string
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "ranges":
			for d.NextArg() {
				ranges = append(ranges, d.Val())
			}
			m.Ranges = ranges
		case "message":
			if !d.NextArg() {
				return d.ArgErr()
			}
			Message := d.Val()
			m.Message = Message
		case "whitelist":
			for d.NextArg() {
				m.Whitelist = append(m.Whitelist, d.Val())
			}
		case "serve_ignore":
			m.ServeIgnore = true
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// UnmarshalJSON handles the Responder interface and converts the interface to a Defender struct
func (m *Defender) UnmarshalJSON(b []byte) error {
	type rawDefender Defender
	var rawConfig rawDefender
	var excludedKeys = []string{"responder"}

	if err := json.Unmarshal(b, &rawConfig); err != nil {
		return err
	}

	switch rawConfig.RawResponder {
	case "block":
		m.responder = &responders.BlockResponder{}
	case "garbage":
		m.responder = &responders.GarbageResponder{}
	case "custom":
		// Get the custom message
		m.Message = rawConfig.Message
		m.responder = &responders.CustomResponder{
			Message: m.Message,
		}
	case "ratelimit":
		m.responder = &responders.RateLimitResponder{}
	default:
		return fmt.Errorf("unknown responder type: %s", rawConfig.RawResponder)
	}

	// Use reflection to copy fields excluding excludedKeys
	rawVal := reflect.ValueOf(rawConfig)
	mVal := reflect.ValueOf(m).Elem()
	rawType := rawVal.Type()

	for i := 0; i < rawVal.NumField(); i++ {
		fieldName := rawType.Field(i).Name
		if slices.Contains(excludedKeys, fieldName) {
			continue
		}
		mField := mVal.FieldByName(fieldName)
		rawField := rawVal.Field(i)
		if mField.IsValid() && mField.CanSet() {
			mField.Set(rawField)
		}
	}

	return nil
}

// Validate ensures the middleware configuration is valid
func (m *Defender) Validate() error {
	if m.responder == nil {
		return fmt.Errorf("responder not configured")
	}

	for _, ipRange := range m.Ranges {
		// Check if the range is a predefined key (e.g., "openai")
		if _, ok := data.IPRanges[ipRange]; ok {
			// If it's a predefined key, skip CIDR validation
			continue
		}

		// Otherwise, treat it as a custom CIDR and validate it
		_, _, err := net.ParseCIDR(ipRange)
		if err != nil {
			return fmt.Errorf("invalid IP range %q: %v", ipRange, err)
		}
	}

	// Check if the whitelist is valid
	err := whitelist.Validate(m.Whitelist)
	if err != nil {
		return err
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Defender
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
