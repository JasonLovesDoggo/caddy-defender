package caddydefender

import (
	"encoding/json"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/jasonlovesdoggo/caddy-defender/responders"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Defender
		expectError bool
		errContains string
	}{
		{
			name: "valid block responder with CIDR ranges",
			input: `defender block {
				ranges 192.168.1.0/24 10.0.0.0/8
			}`,
			expected: Defender{
				RawResponder: "block",
				Ranges:       []string{"192.168.1.0/24", "10.0.0.0/8"},
			},
		},
		{
			name: "valid custom responder with message",
			input: `defender custom {
				ranges openai
				message "Not allowed"
			}`,
			expected: Defender{
				RawResponder: "custom",
				Ranges:       []string{"openai"},
				Message:      "Not allowed",
			},
		},
		{
			name: "valid predefined range key",
			input: `defender garbage {
				ranges cloudflare
			}`,
			expected: Defender{
				RawResponder: "garbage",
				Ranges:       []string{"cloudflare"},
			},
		},
		{
			name: "missing responder type",
			input: `defender {
				ranges 10.0.0.0/8
			}`,
			expectError: true,
			errContains: "missing responder type",
		},
		{
			name: "invalid responder type",
			input: `defender invalid {
				ranges 10.0.0.0/8
			}`,
			expectError: true,
			errContains: "invalid responder type",
		},
		{
			name: "invalid subdirective",
			input: `defender block {
				invalid 123
			}`,
			expectError: true,
			errContains: "unknown subdirective",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			def := new(Defender)

			err := def.UnmarshalCaddyfile(d)

			if tt.expectError {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected.RawResponder, def.RawResponder)
			require.Equal(t, tt.expected.Ranges, def.Ranges)
			require.Equal(t, tt.expected.Message, def.Message)
		})
	}
}

func TestUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Defender
		expectError bool
	}{
		{
			name:  "valid block responder with ranges",
			input: `{"raw_responder":"block","ranges":["10.0.0.0/8","aws"]}`,
			expected: Defender{
				RawResponder: "block",
				Ranges:       []string{"10.0.0.0/8", "aws"},
				responder:    &responders.BlockResponder{},
			},
		},
		{
			name:  "valid custom responder with message",
			input: `{"raw_responder":"custom","message":"Go away","ranges":["openai"]}`,
			expected: Defender{
				RawResponder: "custom",
				Message:      "Go away",
				Ranges:       []string{"openai"},
				responder:    &responders.CustomResponder{Message: "Go away"},
			},
		},
		{
			name:        "invalid responder type",
			input:       `{"raw_responder":"invalid"}`,
			expectError: true,
		},
		{
			name:  "all fields copied except responder",
			input: `{"raw_responder":"block","ranges":["azure"],"message":"test","log":null}`,
			expected: Defender{
				RawResponder: "block",
				Ranges:       []string{"azure"},
				Message:      "test",
				responder:    &responders.BlockResponder{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var def Defender
			err := json.Unmarshal([]byte(tt.input), &def)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected.RawResponder, def.RawResponder)
			require.Equal(t, tt.expected.Ranges, def.Ranges)
			require.Equal(t, tt.expected.Message, def.Message)
			require.IsType(t, tt.expected.responder, def.responder)
		})
	}
}

func TestValidation(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		def := Defender{
			RawResponder: "block",
			Ranges:       []string{"10.0.0.0/8"},
			responder:    &responders.BlockResponder{},
		}
		require.NoError(t, def.Validate())
	})

	t.Run("missing responder", func(t *testing.T) {
		def := Defender{
			Ranges: []string{"10.0.0.0/8"},
		}
		require.ErrorContains(t, def.Validate(), "responder not configured")
	})

	t.Run("invalid CIDR format", func(t *testing.T) {
		def := Defender{
			RawResponder: "block",
			Ranges:       []string{"invalid"},
			responder:    &responders.BlockResponder{},
		}
		require.ErrorContains(t, def.Validate(), "invalid IP range")
	})
}

func TestDefenderValidation(t *testing.T) {
	t.Run("Invalid responder type", func(t *testing.T) {
		caddytest.AssertLoadError(t, `{
  "admin": {
    "disabled": true
  },
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [
            "127.0.0.1:80",
            "[::1]:80"
          ],
          "routes": [
            {
              "handle": [
                {
                  "handler": "defender",
                  "ranges": [
                    "private"
                  ],
                  "raw_responder": "pineapple"
                },
                {
                  "body": "This is what a human sees",
                  "handler": "static_response"
                }
              ]
            }
          ],
          "automatic_https": {
            "disable": true
          }
        },
        "srv1": {
          "listen": [
            "127.0.0.1:83",
            "[::1]:83"
          ],
          "routes": [
            {
              "handle": [
                {
                  "body": "Clear text HTTP",
                  "handler": "static_response"
                }
              ]
            }
          ],
          "automatic_https": {
            "disable": true
          }
        }
      }
    }
  }
}`, "json", "unknown responder type")
	})
}
