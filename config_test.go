package caddydefender

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/jasonlovesdoggo/caddy-defender/responders"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		errContains string
		expected    Defender
		expectError bool
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
			name: "valid drop responder",
			input: `defender drop {
				ranges openai
			}`,
			expected: Defender{
				RawResponder: "drop",
				Ranges:       []string{"openai"},
			},
		},
		{
			name: "valid redirect responder with url",
			input: `defender redirect {
				ranges openai
				url "https://example.com"
			}`,
			expected: Defender{
				RawResponder: "redirect",
				Ranges:       []string{"openai"},
				URL:          "https://example.com",
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
			errContains: "missing responder type",
			expectError: true,
		},
		{
			name: "invalid responder type",
			input: `defender invalid {
				ranges 10.0.0.0/8
			}`,
			errContains: "invalid responder type",
			expectError: true,
		},
		{
			name: "invalid subdirective",
			input: `defender block {
				invalid 123
			}`,
			errContains: "unknown subdirective",
			expectError: true,
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
			name:  "valid drop responder",
			input: `{"raw_responder":"drop","ranges":["openai"]}`,
			expected: Defender{
				RawResponder: "drop",
				Ranges:       []string{"openai"},
				responder:    &responders.DropResponder{},
			},
		},
		{
			name:  "valid redirect responder with url",
			input: `{"raw_responder":"redirect","url":"https://example.com","ranges":["openai"]}`,
			expected: Defender{
				RawResponder: "redirect",
				URL:          "https://example.com",
				Ranges:       []string{"openai"},
				responder:    &responders.RedirectResponder{URL: "https://example.com"},
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
			Whitelist:    []string{"126.39.0.3"},
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

	t.Run("invalid whitelist IP", func(t *testing.T) {
		def := Defender{
			RawResponder: "block",
			Whitelist:    []string{"invalid"},
			responder:    &responders.BlockResponder{},
		}
		require.ErrorContains(t, def.Validate(), "invalid IP address")
	})

	t.Run("Missing ranges", func(t *testing.T) {
		def := Defender{
			RawResponder: "block",
			responder:    &responders.BlockResponder{},
		}
		err := def.Provision(caddy.Context{Context: caddy.ActiveContext()})
		if err != nil {
			return
		}

		// We must sort the ranges to compare them as the order is not guaranteed
		sort.Slice(def.Ranges, func(i, j int) bool {
			return def.Ranges[i] < def.Ranges[j]
		})

		defaultRanges := DefaultRanges

		sort.Slice(defaultRanges, func(i, j int) bool {
			return defaultRanges[i] < defaultRanges[j]
		})

		require.Equal(t, defaultRanges, def.Ranges)
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
                    "raw_responder": "redirect",
                    "ranges": [
                      "private"
                    ]
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
  }`, "json", "redirect responder requires 'url' to be set")
	})
}
