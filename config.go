package caddydefender

import (
	"encoding/json"
	"fmt"
	"github.com/jasonlovesdoggo/caddy-defender/ranges/data"
	"github.com/jasonlovesdoggo/caddy-defender/responders"
	"net"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (m *DefenderMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Skip the "defender" token
	if !d.Next() {
		return d.Err("expected defender directive")
	}

	// Get the responder type
	if !d.NextArg() {
		return d.ArgErr()
	}
	responderType := d.Val()

	// Build middleware structure
	middleware := map[string]interface{}{}

	// Handle responder configuration
	var responderConfig map[string]interface{}
	switch responderType {
	case "block":
		responderConfig = map[string]interface{}{"type": "block"}
	case "garbage":
		responderConfig = map[string]interface{}{"type": "garbage"}
	case "custom":
		if !d.NextArg() {
			return d.ArgErr()
		}
		responderConfig = map[string]interface{}{
			"type":    "custom",
			"message": d.Val(),
		}
	case "file":
		if !d.NextArg() {
			return d.ArgErr()
		}
		filePath := d.Val()
		headers := make(map[string]string)
		for d.NextArg() {
			header := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			headers[header] = d.Val()
		}
		responderConfig = map[string]interface{}{
			"type":    "file",
			"file":    filePath,
			"headers": headers,
		}
	default:
		return d.Errf("unknown responder type: %s", responderType)
	}

	middleware["responder"] = responderConfig

	// Parse the block if it exists
	var ranges []string
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "ranges":
			for d.NextArg() {
				ranges = append(ranges, d.Val())
			}
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	if len(ranges) > 0 {
		middleware["additional_ranges"] = ranges
	}

	// Marshal the complete middleware structure
	rawJSON, err := json.Marshal(middleware)
	if err != nil {
		return fmt.Errorf("marshaling middleware config: %v", err)
	}

	// Unmarshal into the middleware struct
	return json.Unmarshal(rawJSON, m)
}

// UnmarshalJSON handles the responder interface
func (m *DefenderMiddleware) UnmarshalJSON(b []byte) error {
	type tempMiddleware DefenderMiddleware
	var temp tempMiddleware
	if err := json.Unmarshal(b, &temp); err != nil {
		return err
	}

	m.AdditionalRanges = temp.AdditionalRanges
	m.ResponderRaw = temp.ResponderRaw

	if len(m.ResponderRaw) == 0 {
		return fmt.Errorf("missing responder configuration")
	}

	var responderMap map[string]interface{}
	if err := json.Unmarshal(m.ResponderRaw, &responderMap); err != nil {
		return err
	}

	responderType, ok := responderMap["type"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid responder type")
	}

	switch responderType {
	case "block":
		m.responder = &responders.BlockResponder{}
	case "garbage":
		m.responder = &responders.GarbageResponder{}
	case "custom":
		var customResp responders.CustomResponder
		if err := json.Unmarshal(m.ResponderRaw, &customResp); err != nil {
			return err
		}
		m.responder = &customResp
	case "file":
		var fileResp responders.FileResponder
		if err := json.Unmarshal(m.ResponderRaw, &fileResp); err != nil {
			return err
		}
		m.responder = &fileResp
	default:
		return fmt.Errorf("unknown responder type: %s", responderType)
	}

	return nil
}

// Validate ensures the middleware configuration is valid
func (m *DefenderMiddleware) Validate() error {
	if m.responder == nil {
		return fmt.Errorf("responder not configured")
	}

	for _, ipRange := range m.AdditionalRanges {
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

	return nil
}
