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

	// Load existing IPs from file if it exists
	if _, err := os.Stat(filePath); err == nil {
		if err := d.loadFromFileUnsafe(); err != nil {
			d.log.Warn("Failed to load existing dynamic IPs from file",
				zap.String("file", filePath),
				zap.Error(err))
		}
	}

	return nil
}

// loadFromFileUnsafe loads IPs from file (must be called with lock held)
func (d *dynamicBlocklist) loadFromFileUnsafe() error {
	file, err := os.Open(d.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Only load lines marked as dynamic
		if strings.HasPrefix(line, "# [DYNAMIC] ") {
			ip := strings.TrimPrefix(line, "# [DYNAMIC] ")
			d.ips[ip] = true
		}
	}

	return scanner.Err()
}

// saveToFile persists the current dynamic blocklist to file
func (d *dynamicBlocklist) saveToFile() error {
	if !d.persistToFile || d.filePath == "" {
		return nil
	}

	// Read existing file content
	var existingLines []string
	if _, err := os.Stat(d.filePath); err == nil {
		file, err := os.Open(d.filePath)
		if err != nil {
			return fmt.Errorf("failed to read existing file: %w", err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			// Skip lines that were dynamically added (we'll re-add them)
			if !strings.HasPrefix(line, "# [DYNAMIC] ") {
				existingLines = append(existingLines, line)
			}
		}
		file.Close()
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to scan file: %w", err)
		}
	}

	// Write back existing content plus dynamic IPs
	file, err := os.Create(d.filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Write existing static entries
	for _, line := range existingLines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write line: %w", err)
		}
	}

	// Write dynamic entries with marker
	if len(d.ips) > 0 {
		if len(existingLines) > 0 {
			writer.WriteString("\n# Dynamically added IPs via Admin API\n")
		} else {
			writer.WriteString("# Dynamically added IPs via Admin API\n")
		}
		for ip := range d.ips {
			if _, err := writer.WriteString(fmt.Sprintf("# [DYNAMIC] %s\n", ip)); err != nil {
				return fmt.Errorf("failed to write dynamic IP: %w", err)
			}
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
