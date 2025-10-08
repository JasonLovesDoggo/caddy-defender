package caddydefender

import (
	"sync"

	"go.uber.org/zap"
)

// dynamicBlocklist manages runtime IP blocking with thread-safe operations
type dynamicBlocklist struct {
	ips map[string]bool // map for O(1) lookups
	mu  sync.RWMutex
	log *zap.Logger
}

func newDynamicBlocklist(log *zap.Logger) *dynamicBlocklist {
	return &dynamicBlocklist{
		ips: make(map[string]bool),
		log: log,
	}
}

// Add adds one or more IPs to the dynamic blocklist
func (d *dynamicBlocklist) Add(ips ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, ip := range ips {
		d.ips[ip] = true
	}
	d.log.Info("Added IPs to dynamic blocklist", zap.Strings("ips", ips))
}

// Remove removes an IP from the dynamic blocklist
func (d *dynamicBlocklist) Remove(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.ips[ip]; exists {
		delete(d.ips, ip)
		d.log.Info("Removed IP from dynamic blocklist", zap.String("ip", ip))
		return true
	}
	return false
}

// List returns all IPs in the dynamic blocklist
func (d *dynamicBlocklist) List() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ips := make([]string, 0, len(d.ips))
	for ip := range d.ips {
		ips = append(ips, ip)
	}
	return ips
}

// Contains checks if an IP is in the dynamic blocklist
func (d *dynamicBlocklist) Contains(ip string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.ips[ip]
}

// NOTE: Admin API routes are now implemented in admin_app.go via the DefenderAdmin module.
// This keeps the dynamicBlocklist struct and methods here for use by both the middleware
// and the admin API module.
