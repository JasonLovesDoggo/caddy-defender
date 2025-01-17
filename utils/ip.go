package utils

import (
	"fmt"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/jasonlovesdoggo/caddy-defender/ranges/data"
	"go.uber.org/zap"
	"maps"
	"net"
	"slices"
	"time"
)

const MaxKeys = 10000

var cache = expirable.NewLRU[string, bool](MaxKeys, nil, time.Minute*10)

var PredefinedRangeKeys []string

func init() {
	PredefinedRangeKeys = slices.Collect(maps.Keys(data.IPRanges))
}

// normalizeIP converts an IP to its normalized string representation.
func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// rawIPInRanges checks if the given IP is in the given CIDR ranges without using the cache.
func rawIPInRanges(clientIP net.IP, cidrRanges []string, log *zap.Logger) bool {
	log.Debug(fmt.Sprintf("Checking IP %v against ranges %v", clientIP, cidrRanges))
	for _, cidr := range cidrRanges {
		// If the range is a predefined key (e.g., "openai"), use the corresponding CIDRs
		if ranges, ok := data.IPRanges[cidr]; ok {
			for _, predefinedCIDR := range ranges {
				_, ipNet, err := net.ParseCIDR(predefinedCIDR)
				if err != nil {
					log.Error(fmt.Sprintf("Invalid predefined CIDR: %v", err))
					continue
				}
				if ipNet.Contains(clientIP) {
					return true
				}
			}
		} else {
			// Otherwise, treat it as a custom CIDR
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Error(fmt.Sprintf("Invalid CIDR: %v", err))
				continue
			}
			if ipNet.Contains(clientIP) {
				return true
			}
		}
	}
	return false
}

// IPInRanges checks if the given IP is within any of the provided CIDR ranges.
// It returns true if the IP is in any of the ranges, false otherwise.
func IPInRanges(clientIP net.IP, cidrRanges []string, log *zap.Logger) bool {
	// Normalize the IP for consistent cache keys
	cacheKey := normalizeIP(clientIP)

	// Check the cache first
	if val, ok := cache.Get(cacheKey); ok {
		return val
	}

	// If not in the cache, check the ranges
	inRanges := rawIPInRanges(clientIP, cidrRanges, log)

	// Add the result to the cache
	cache.Add(cacheKey, inRanges)

	return inRanges
}
