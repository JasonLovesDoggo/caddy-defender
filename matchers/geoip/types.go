package geoip

import (
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"time"
)

// Config holds the initialization parameters for GeoIP
type Config struct {
	DatabasePath string
	CacheTTL     time.Duration
}

func (c Config) Enabled() bool {
	return c.DatabasePath != ""

}

func (c Config) Provision() (*Handler, error) {
	h := &Handler{
		logger: zap.NewNop(),
	}

	if err := h.Initialize(c); err != nil {
		return nil, err
	}

	return h, nil
}

func (c Config) Validate() error {
	// if CacheTTL is set, DatabasePath must be set
	if c.CacheTTL > 0 && c.DatabasePath == "" {
		return fmt.Errorf("cache TTL set but no database path provided")
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("cache TTL must be a positive duration")
	}
	if c.DatabasePath == "" {
		return fmt.Errorf("no database path provided")
	}

	// Attempt to open the database to ensure it's valid
	_, err := maxminddb.Open(c.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to load database: %w", err)
	}

	return nil
}

type CountryRecord struct {
	ISOCode string `maxminddb:"iso_code"`
}

type GeoRecord struct {
	Country CountryRecord `maxminddb:"country"`
}
