package ip

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	Whitelist "pkg.jsn.cam/caddy-defender/matchers/whitelist"

	"github.com/gaissmai/bart"
	"github.com/viccon/sturdyc"
	"go.uber.org/zap"
	"pkg.jsn.cam/caddy-defender/ranges/data"
)

type IPChecker struct {
	table     *bart.Table[struct{}]
	cache     *sturdyc.Client[string]
	whitelist *Whitelist.Whitelist
	log       *zap.Logger
	mu        sync.RWMutex // Protects table for dynamic updates
}

func NewIPChecker(cidrRanges, whitelistedIPs []string, log *zap.Logger) *IPChecker {
	const (
		capacity        = 10000
		numShards       = 10
		ttl             = 10 * time.Minute
		evictionPercent = 10
		minRefreshDelay = 100 * time.Millisecond
		maxRefreshDelay = 300 * time.Millisecond
		retryBaseDelay  = 10 * time.Millisecond
	)

	whitelist, err := Whitelist.Initialize(whitelistedIPs)
	if err != nil {
		log.Warn("Invalid whitelist IP",
			zap.Strings("whitelist", whitelistedIPs),
			zap.Error(err))
	}

	cache := sturdyc.New[string](
		capacity,
		numShards,
		ttl,
		evictionPercent,
		sturdyc.WithEarlyRefreshes(
			minRefreshDelay,
			maxRefreshDelay,
			ttl,
			retryBaseDelay,
		),
		sturdyc.WithMissingRecordStorage(),
	)

	return &IPChecker{
		table:     buildTable(cidrRanges, log),
		cache:     cache,
		log:       log,
		whitelist: whitelist,
	}
}

func (c *IPChecker) ReqAllowed(ctx context.Context, clientIP net.IP) bool {
	// convert net.IP to netip.Addr
	ipAddr, err := ipToAddr(clientIP)
	if err != nil {
		c.log.Warn("Invalid IP address format",
			zap.String("ip", clientIP.String()),
			zap.Error(err))
		return false
	}

	// Check if the IP is whitelisted
	if ok, _ := c.whitelist.Matches(ipAddr); ok {
		c.log.Debug("IP is whitelisted", zap.String("ip", clientIP.String()))
		return true
	}
	// Check if the IP is in the blocked ranges
	return !c.IPInRanges(ctx, ipAddr)
}

func (c *IPChecker) IPInRanges(ctx context.Context, ipAddr netip.Addr) bool {
	// Convert to netip.Addr first to handle IPv4-mapped IPv6 addresses
	// Use the normalized string representation for cache keys
	cacheKey := ipAddr.String()

	result, _ := c.cache.GetOrFetch(ctx, cacheKey, func(ctx context.Context) (string, error) {
		c.mu.RLock()
		contains := c.table.Contains(ipAddr)
		c.mu.RUnlock()

		if contains {
			return "true", nil
		}
		return "false", sturdyc.ErrNotFound
	})

	return result == "true"
}

// UpdateRanges dynamically updates the IP ranges in the routing table
func (c *IPChecker) UpdateRanges(cidrRanges []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build a new table with the updated ranges
	c.table = buildTable(cidrRanges, c.log)

	// Create a new cache instance to ensure fresh lookups with new ranges
	// (sturdyc doesn't provide a "clear all" method, so we recreate the cache)
	const (
		capacity        = 10000
		numShards       = 10
		ttl             = 10 * time.Minute
		evictionPercent = 10
		minRefreshDelay = 100 * time.Millisecond
		maxRefreshDelay = 300 * time.Millisecond
		retryBaseDelay  = 10 * time.Millisecond
	)

	c.cache = sturdyc.New[string](
		capacity,
		numShards,
		ttl,
		evictionPercent,
		sturdyc.WithEarlyRefreshes(
			minRefreshDelay,
			maxRefreshDelay,
			ttl,
			retryBaseDelay,
		),
		sturdyc.WithMissingRecordStorage(),
	)

	c.log.Info("IP ranges updated dynamically",
		zap.Int("range_count", len(cidrRanges)))
}

func buildTable(cidrRanges []string, log *zap.Logger) *bart.Table[struct{}] {
	table := &bart.Table[struct{}]{}
	for _, cidr := range cidrRanges {
		if ranges, ok := data.IPRanges[cidr]; ok {
			for _, predefinedCIDR := range ranges {
				if err := insertCIDR(table, predefinedCIDR); err != nil {
					log.Warn("Invalid predefined CIDR",
						zap.String("group", cidr),
						zap.String("cidr", predefinedCIDR),
						zap.Error(err))
				}
			}
			continue
		}

		if err := insertCIDR(table, cidr); err != nil {
			log.Warn("Invalid CIDR specification",
				zap.String("cidr", cidr),
				zap.Error(err))
		}
	}
	return table
}

func insertCIDR(table *bart.Table[struct{}], cidr string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Always insert the original CIDR
	table.Insert(prefix.Masked(), struct{}{})

	// If IPv4 CIDR, also insert as IPv4-mapped IPv6
	if prefix.Addr().Is4() {
		ipv4 := prefix.Addr().As4()
		ipv6Bytes := [16]byte{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
			ipv4[0], ipv4[1], ipv4[2], ipv4[3],
		}
		ipv6Prefix := netip.PrefixFrom(
			netip.AddrFrom16(ipv6Bytes),
			96+prefix.Bits(), // Convert IPv4 prefix to IPv4-mapped IPv6
		)
		table.Insert(ipv6Prefix.Masked(), struct{}{})
	}

	return nil
}

func ipToAddr(ip net.IP) (netip.Addr, error) {
	if ip == nil {
		return netip.Addr{}, fmt.Errorf("ip is nil")
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}
	return addr, nil
}
