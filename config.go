package caddydefender

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/jasonlovesdoggo/caddy-defender/ranges/data"
	"github.com/jasonlovesdoggo/caddy-defender/responders"
	"maps"
	"net"
	"os"
	"slices"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//		defender <responder> {
//		# IP ranges to block (optional)
//		ranges
//	 # file containing IP ranges to block (optional)
//	 ranges_file
//	 # Custom message to return to the client when using "custom" middleware (optional)
//	 message
//		}
func (m *Defender) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Skip the "defender" token
	if !d.Next() {
		return d.Err("expected defender directive")
	}

	// Get the responder type
	if !d.NextArg() {
		return d.ArgErr()
	}
	m.RawResponder = d.Val()

	// Parse the block if it exists
	var ranges []string
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "ranges":
			for d.NextArg() {
				ranges = append(ranges, d.Val())
			}
		case "ranges_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.RangesFile = d.Val()
		case "message":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Message = d.Val()
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	if len(ranges) > 0 {
		m.Ranges = ranges
	}

	return nil
}

// UnmarshalJSON handles the Responder interface
func (m *Defender) UnmarshalJSON(b []byte) error {
	type rawDefender Defender
	var rawConfig rawDefender
	if err := json.Unmarshal(b, &rawConfig); err != nil {
		return err
	}

	switch rawConfig.RawResponder {
	case "block":
		m.responder = &responders.BlockResponder{}
	case "garbage":
		m.responder = &responders.GarbageResponder{}
	case "custom":
		var customResp responders.CustomResponder
		customResp.Message = &m.Message
		m.responder = &customResp
	default:
		return fmt.Errorf("unknown responder type: %s", rawConfig.RawResponder)
	}

	return nil
}

// Validate ensures the middleware configuration is valid
func (m *Defender) Validate() error {
	if m.responder == nil {
		return fmt.Errorf("responder not configured")
	}
	if len(m.Ranges) == 0 && m.RangesFile == "" {
		// set the default ranges to be all of the predefined ranges
		m.Ranges = slices.Collect(maps.Keys(data.IPRanges))
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

	// Validate ranges loaded from the text file
	if m.RangesFile != "" {
		file, err := os.Open(m.RangesFile)
		if err != nil {
			return fmt.Errorf("failed to open ranges file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			_, _, err := net.ParseCIDR(line)
			if err != nil {
				return fmt.Errorf("invalid IP range in file %q: %v", line, err)
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading ranges file: %v", err)
		}
	}

	return nil
}
