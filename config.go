package caddydefender

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"pkg.jsn.cam/caddy-defender/matchers/whitelist"
	"pkg.jsn.cam/caddy-defender/ranges/data"
	"pkg.jsn.cam/caddy-defender/responders"
	"pkg.jsn.cam/caddy-defender/responders/tarpit"
)

var responderTypes = []string{"block", "custom", "drop", "garbage", "ratelimit", "redirect", "tarpit"}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	defender <responder> {
//		# IP ranges to block
//		ranges
//		# Whitelisted IP addresses to allow to bypass ranges (optional)
//		whitelist
//	    # Custom message to return to the client when using "custom" middleware (optional)
//	    message
//	    # Custom URL to redirect the client to when using "redirect" middleware (optional)
//	    url
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
			m.Ranges = ranges
		case "message":
			if !d.NextArg() {
				return d.ArgErr()
			}
			Message := d.Val()
			m.Message = Message
		case "status_code":
			if !d.NextArg() {
				return d.ArgErr()
			}
			statusCode, err := strconv.Atoi(d.Val())
			if err != nil {
				return fmt.Errorf("invalid status_code value: '%s'", d.Val())
			}
			m.StatusCode = statusCode
		case "url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			url := d.Val()
			m.URL = url
		case "whitelist":
			for d.NextArg() {
				m.Whitelist = append(m.Whitelist, d.Val())
			}
		case "serve_ignore":
			m.ServeIgnore = true
		case "tarpit_config":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "headers":
					headers := map[string]string{}
					for nesting := d.Nesting(); d.NextBlock(nesting); {
						k := d.Val()
						if !d.NextArg() {
							return d.ArgErr()
						}
						headers[k] = d.Val()
					}
					m.TarpitConfig.Headers = headers
				case "content":
					if !d.NextArg() {
						return d.ArgErr()
					}

					content := strings.Split(d.Val(), "://")
					if len(content) != 2 {
						return errors.New("invalid content format. expected <content protocol>://<content path>")
					}

					m.TarpitConfig.Content = tarpit.Content{
						Protocol: content[0],
						Path:     content[1],
					}
				case "timeout":
					if !d.NextArg() {
						return d.ArgErr()
					}

					timeout, err := time.ParseDuration(d.Val())
					if err != nil {
						return fmt.Errorf("invalid timeout value: '%s'", d.Val())
					}

					m.TarpitConfig.Timeout = timeout
				case "bytes_per_second":
					if !d.NextArg() {
						return d.ArgErr()
					}

					bps, err := strconv.Atoi(d.Val())
					if err != nil {
						return fmt.Errorf("invalid bytes_per_second value: '%s'", d.Val())
					}

					m.TarpitConfig.BytesPerSecond = bps
				case "response_code":
					if !d.NextArg() {
						return d.ArgErr()
					}

					responseCode, err := strconv.Atoi(d.Val())
					if err != nil {
						return fmt.Errorf("invalid response_code value: '%s'", d.Val())
					}

					m.TarpitConfig.ResponseCode = responseCode
				default:
					return d.Errf("unknown nested config key: %s", d.Val())
				}
			}
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
	case "custom":
		// Get the custom message and status code
		m.Message = rawConfig.Message
		m.StatusCode = rawConfig.StatusCode
		m.responder = &responders.CustomResponder{
			Message:    m.Message,
			StatusCode: m.StatusCode,
		}
	case "drop":
		m.responder = &responders.DropResponder{}
	case "garbage":
		m.responder = &responders.GarbageResponder{}
	case "ratelimit":
		m.responder = &responders.RateLimitResponder{}
	case "redirect":
		m.URL = rawConfig.URL
		m.responder = &responders.RedirectResponder{
			URL: m.URL,
		}
	case "tarpit":
		m.responder = &tarpit.Responder{
			Config: &m.TarpitConfig,
		}

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

	// Validate responder config options
	if m.RawResponder == "redirect" && m.URL == "" {
		return errors.New("redirect responder requires 'url' to be set")
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Defender
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
