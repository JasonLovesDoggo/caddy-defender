package ratelimit

import "time"

// Config holds the configuration for rate limiting based on HTTP status codes
type Config struct {
	// Enabled determines if rate limiting is active
	Enabled bool `json:"enabled"`

	// StatusCodes defines which HTTP status codes to track (e.g., [404])
	// Default: [404]
	StatusCodes []int `json:"status_codes,omitempty"`

	// MaxRequests is the maximum number of tracked status codes allowed within the window
	// Default: 10
	MaxRequests int `json:"max_requests,omitempty"`

	// WindowDuration is the time window for counting requests
	// Default: 5m
	WindowDuration time.Duration `json:"window_duration,omitempty"`

	// AutoAddToBlocklist determines if IPs exceeding the limit should be automatically blocked
	// Default: true
	AutoAddToBlocklist bool `json:"auto_add_to_blocklist,omitempty"`

	// CleanupInterval is how often to purge old tracking data
	// Default: 10m
	CleanupInterval time.Duration `json:"cleanup_interval,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Enabled:            false, // Opt-in feature
		StatusCodes:        []int{404},
		MaxRequests:        10,
		WindowDuration:     5 * time.Minute,
		AutoAddToBlocklist: true,
		CleanupInterval:    10 * time.Minute,
	}
}

// ApplyDefaults fills in any missing configuration values with defaults
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	if len(c.StatusCodes) == 0 {
		c.StatusCodes = defaults.StatusCodes
	}
	if c.MaxRequests == 0 {
		c.MaxRequests = defaults.MaxRequests
	}
	if c.WindowDuration == 0 {
		c.WindowDuration = defaults.WindowDuration
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = defaults.CleanupInterval
	}
}
