package geoip

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

/*
geoip {
   db_path /path/to/file.mmdb
   cache_ttl  40s
}
*/

// Handler manages GeoIP lookups and caching
type Handler struct {
	logger     *zap.Logger
	db         *maxminddb.Reader
	cache      map[netip.Addr]GeoRecord
	cacheMutex sync.RWMutex
	cacheTTL   time.Duration
}

// Initialize sets up the Handler with the provided configuration
func (h *Handler) Initialize(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	db, err := maxminddb.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to load database: %w", err)
	}

	h.db = db
	h.cacheTTL = cfg.CacheTTL

	if h.cacheTTL > 0 {
		h.cache = make(map[netip.Addr]GeoRecord)
	}

	h.logger.Info("geoip initialized",
		zap.String("database_path", cfg.DatabasePath),
		zap.Duration("cache_ttl", cfg.CacheTTL),
	)

	return nil
}

// Close releases the database resources
func (h *Handler) Close() error {
	if h.db != nil {
		return h.db.Close()
	}
	return nil
}

// Matches checks if an IP address belongs to any country in the provided list
func (h *Handler) Matches(addr netip.Addr, allowedCountries []string) (bool, error) {
	if h.db == nil {
		return false, fmt.Errorf("database not initialized")
	}

	record, err := h.lookupAddr(addr)
	if err != nil {
		h.logger.Error("lookup failed",
			zap.String("addr", addr.String()),
			zap.Error(err))
		return false, err
	}

	return h.isCountryAllowed(record, allowedCountries), nil
}

// GetCountry returns the country code for an IP address
func (h *Handler) GetCountry(addr netip.Addr) (string, error) {
	if h.db == nil {
		return "", fmt.Errorf("database not initialized")
	}

	record, err := h.lookupAddr(addr)
	if err != nil {
		h.logger.Debug("lookup failed",
			zap.String("addr", addr.String()),
			zap.Error(err))
		return "", err
	}

	return record.Country.ISOCode, nil
}

// lookupAddr performs the GeoIP lookup with caching if enabled
func (h *Handler) lookupAddr(addr netip.Addr) (GeoRecord, error) {
	// Check cache first if enabled
	if h.cache != nil {
		h.cacheMutex.RLock()
		if record, exists := h.cache[addr]; exists {
			h.cacheMutex.RUnlock()
			return record, nil
		}
		h.cacheMutex.RUnlock()
	}

	var record GeoRecord
	err := h.db.Lookup(addr.AsSlice(), &record)
	if err != nil {
		return GeoRecord{}, err
	}

	// Cache the result if caching is enabled
	if h.cache != nil {
		h.cacheRecord(addr, record)
	}

	return record, nil
}

// isCountryAllowed checks if the country from the record is in the allowed list
func (h *Handler) isCountryAllowed(record GeoRecord, allowedCountries []string) bool {
	for _, country := range allowedCountries {
		if strings.EqualFold(record.Country.ISOCode, country) {
			return true
		}
	}
	return false
}

// cacheRecord stores a record in the cache with TTL
func (h *Handler) cacheRecord(addr netip.Addr, record GeoRecord) {
	h.cacheMutex.Lock()
	h.cache[addr] = record
	h.cacheMutex.Unlock()

	if h.cacheTTL > 0 {
		time.AfterFunc(h.cacheTTL, func() {
			h.cacheMutex.Lock()
			delete(h.cache, addr)
			h.cacheMutex.Unlock()
		})
	}
}
