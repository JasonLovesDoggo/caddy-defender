package caddydefender

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// dynamicBlocklist manages runtime IP blocking with thread-safe operations
type dynamicBlocklist struct {
	ips          map[string]bool // map for O(1) lookups
	mu           sync.RWMutex
	log          *zap.Logger
	filePath     string // optional file path for persistence
	persistToFile bool   // whether to persist changes to file
}

func newDynamicBlocklist(log *zap.Logger) *dynamicBlocklist {
	return &dynamicBlocklist{
		ips: make(map[string]bool),
		log: log,
	}
}

// EnableFilePersistence enables persisting dynamic blocklist to a file
func (d *dynamicBlocklist) EnableFilePersistence(filePath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.filePath = filePath
	d.persistToFile = true

	d.log.Info("Dynamic blocklist file persistence enabled",
		zap.String("file", filePath))

	return nil
}

// saveToFile persists the current dynamic blocklist to file
func (d *dynamicBlocklist) saveToFile() error {
	if !d.persistToFile || d.filePath == "" {
		return nil
	}

	// Read existing file content to preserve non-dynamic entries
	existingIPs := make(map[string]bool)
	if _, err := os.Stat(d.filePath); err == nil {
		file, err := os.Open(d.filePath)
		if err != nil {
			return fmt.Errorf("failed to read existing file: %w", err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Keep track of existing IPs (these are static/file-based)
			existingIPs[line] = true
		}
		file.Close()
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to scan file: %w", err)
		}
	}

	// Create a set of all IPs: existing static + dynamic
	allIPs := make(map[string]bool)
	for ip := range existingIPs {
		allIPs[ip] = true
	}
	for ip := range d.ips {
		allIPs[ip] = true
	}

	// Write all IPs to file
	file, err := os.Create(d.filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Write all IPs (both static and dynamic)
	for ip := range allIPs {
		if _, err := writer.WriteString(ip + "\n"); err != nil {
			return fmt.Errorf("failed to write IP: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// Add adds one or more IPs to the dynamic blocklist
func (d *dynamicBlocklist) Add(ips ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, ip := range ips {
		d.ips[ip] = true
	}

	// Persist to file if enabled
	if err := d.saveToFile(); err != nil {
		d.log.Error("Failed to persist dynamic blocklist to file",
			zap.Error(err))
		return err
	}

	d.log.Info("Added IPs to dynamic blocklist", zap.Strings("ips", ips))
	return nil
}

// Remove removes an IP from the dynamic blocklist
func (d *dynamicBlocklist) Remove(ip string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.ips[ip]; exists {
		delete(d.ips, ip)

		// Persist to file if enabled
		if err := d.saveToFile(); err != nil {
			d.log.Error("Failed to persist dynamic blocklist to file",
				zap.Error(err))
			return true, err
		}

		d.log.Info("Removed IP from dynamic blocklist", zap.String("ip", ip))
		return true, nil
	}
	return false, nil
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
