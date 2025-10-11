package caddydefender

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

var (
	// globalDefenderAdmin holds the singleton instance
	globalDefenderAdmin *DefenderAdmin
	globalAdminMu       sync.RWMutex
)

// IPRangeFetcher defines the interface for fetching IP ranges from a source
type IPRangeFetcher interface {
	FetchIPRanges() ([]string, error)
}

func init() {
	caddy.RegisterModule(DefenderAdmin{})
}

// DefenderAdmin is an App module that provides admin API routes for managing Defender
type DefenderAdmin struct {
	ctx caddy.Context
	log *zap.Logger

	defender *Defender
	mu       sync.RWMutex
}

// CaddyModule returns the Caddy module information
func (DefenderAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.defender",
		New: func() caddy.Module { return new(DefenderAdmin) },
	}
}

// Provision sets up the DefenderAdmin module
func (d *DefenderAdmin) Provision(ctx caddy.Context) error {
	d.ctx = ctx
	d.log = ctx.Logger(d)

	// Set the global instance so Defender middleware can register
	globalAdminMu.Lock()
	globalDefenderAdmin = d
	globalAdminMu.Unlock()

	d.log.Info("DefenderAdmin provisioned - admin API routes will be available")

	return nil
}

// Start is called after all modules are provisioned
func (d *DefenderAdmin) Start() error {
	d.mu.RLock()
	hasDefender := d.defender != nil
	d.mu.RUnlock()

	d.log.Info("DefenderAdmin started", zap.Bool("defender_registered", hasDefender))
	return nil
}

// Stop is called when the app is shutting down
func (d *DefenderAdmin) Stop() error {
	// Clear the global instance
	globalAdminMu.Lock()
	globalDefenderAdmin = nil
	globalAdminMu.Unlock()

	d.log.Info("DefenderAdmin stopped")
	return nil
}

// RegisterDefender allows a Defender middleware instance to register itself
func (d *DefenderAdmin) RegisterDefender(id string, defender *Defender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.defender = defender
	d.log.Debug("Registered Defender instance", zap.String("id", id))
}

// UnregisterDefender removes the Defender instance from the registry
func (d *DefenderAdmin) UnregisterDefender(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.defender = nil
	d.log.Debug("Unregistered Defender instance", zap.String("id", id))
}

// getDefender retrieves the registered Defender instance
func (d *DefenderAdmin) getDefender() *Defender {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.defender
}

// Routes implements caddy.AdminRouter to add API endpoints
func (d *DefenderAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/defender/blocklist",
			Handler: caddy.AdminHandlerFunc(d.handleBlocklist),
		},
		{
			Pattern: "/defender/blocklist/*",
			Handler: caddy.AdminHandlerFunc(d.handleBlocklistItem),
		},
		{
			Pattern: "/defender/stats",
			Handler: caddy.AdminHandlerFunc(d.handleStats),
		},
	}
}

// handleBlocklist handles GET and POST for /defender/blocklist
func (d *DefenderAdmin) handleBlocklist(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	switch r.Method {
	case http.MethodGet:
		return d.handleGetBlocklist(w, r, defender)
	case http.MethodPost:
		return d.handleAddToBlocklist(w, r, defender)
	default:
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}
}

// handleGetBlocklist returns all blocked IPs from the blocklist file
func (d *DefenderAdmin) handleGetBlocklist(w http.ResponseWriter, r *http.Request, m *Defender) error {
	if m.BlocklistFile == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "blocklist_file must be configured to use the Admin API",
		}
	}

	fileFetcher, ok := m.fileFetcher.(IPRangeFetcher)
	if !ok {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    "file fetcher not available",
		}
	}

	ips, err := fileFetcher.FetchIPRanges()
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to read blocklist file: %v", err),
		}
	}

	response := map[string]interface{}{
		"total": len(ips),
		"ips":   ips,
		"file":  m.BlocklistFile,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleAddToBlocklist adds IPs to the blocklist file
func (d *DefenderAdmin) handleAddToBlocklist(w http.ResponseWriter, r *http.Request, m *Defender) error {
	if m.BlocklistFile == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "blocklist_file must be configured to use the Admin API",
		}
	}

	var req struct {
		IPs []string `json:"ips"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid JSON: %v", err),
		}
	}

	if len(req.IPs) == 0 {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "no IPs provided",
		}
	}

	// Validate IPs are in CIDR format
	for _, ip := range req.IPs {
		if !strings.Contains(ip, "/") {
			return caddy.APIError{
				HTTPStatus: http.StatusBadRequest,
				Message:    fmt.Sprintf("IP must be in CIDR format (e.g., %s/32): %s", ip, ip),
			}
		}
	}

	// Add IPs to the file directly
	if err := d.addIPsToFile(m.BlocklistFile, req.IPs); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to add IPs to blocklist file: %v", err),
		}
	}

	// File watcher will automatically detect the change and update IPChecker

	response := map[string]interface{}{
		"added": req.IPs,
		"count": len(req.IPs),
		"file":  m.BlocklistFile,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(response)
}

// handleBlocklistItem handles DELETE for /defender/blocklist/{ip}
func (d *DefenderAdmin) handleBlocklistItem(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	if r.Method != http.MethodDelete {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	if defender.BlocklistFile == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "blocklist_file must be configured to use the Admin API",
		}
	}

	// Extract IP from path (remove "/defender/blocklist/" prefix)
	path := strings.TrimPrefix(r.URL.Path, "/defender/blocklist/")
	ip := strings.TrimSpace(path)

	if ip == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Message:    "IP address required",
		}
	}

	// Remove IP from file
	removed, err := d.removeIPFromFile(defender.BlocklistFile, ip)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to remove IP from blocklist file: %v", err),
		}
	}
	if !removed {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Message:    fmt.Sprintf("IP not found in blocklist: %s", ip),
		}
	}

	// File watcher will automatically detect the change and update IPChecker

	response := map[string]interface{}{
		"removed": ip,
		"file":    defender.BlocklistFile,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleStats returns statistics about blocked requests
func (d *DefenderAdmin) handleStats(w http.ResponseWriter, r *http.Request) error {
	defender := d.getDefender()
	if defender == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "no defender instances available",
		}
	}

	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	fileCount := 0
	if defender.BlocklistFile != "" {
		fileFetcher, ok := defender.fileFetcher.(IPRangeFetcher)
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			fileCount = len(fileRanges)
		}
	}

	response := map[string]interface{}{
		"configured_ranges": defender.Ranges,
		"blocklist_file":    defender.BlocklistFile,
		"counts": map[string]int{
			"configured_ranges": len(defender.Ranges),
			"file_ranges":       fileCount,
			"total":             len(defender.Ranges) + fileCount,
		},
		"responder": defender.RawResponder,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// addIPsToFile appends IPs to the blocklist file
func (d *DefenderAdmin) addIPsToFile(filePath string, ips []string) error {
	// Read existing IPs
	existingIPs := make(map[string]bool)
	if file, err := os.Open(filePath); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				existingIPs[line] = true
			}
		}
		file.Close()
	}

	// Add new IPs
	for _, ip := range ips {
		existingIPs[ip] = true
	}

	// Write all IPs back to file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for ip := range existingIPs {
		if _, err := writer.WriteString(ip + "\n"); err != nil {
			return fmt.Errorf("failed to write IP: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	d.log.Info("Added IPs to blocklist file",
		zap.String("file", filePath),
		zap.Strings("ips", ips))

	return nil
}

// removeIPFromFile removes an IP from the blocklist file
func (d *DefenderAdmin) removeIPFromFile(filePath string, ipToRemove string) (bool, error) {
	// Read existing IPs
	ips := make([]string, 0)
	found := false

	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == ipToRemove {
			found = true
			continue // Skip the IP to remove
		}
		ips = append(ips, line)
	}
	file.Close()

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to scan file: %w", err)
	}

	if !found {
		return false, nil
	}

	// Write remaining IPs back to file
	file, err = os.Create(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		if _, err := writer.WriteString(ip + "\n"); err != nil {
			return false, fmt.Errorf("failed to write IP: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return false, fmt.Errorf("failed to flush writer: %w", err)
	}

	d.log.Info("Removed IP from blocklist file",
		zap.String("file", filePath),
		zap.String("ip", ipToRemove))

	return true, nil
}

// Interface guards
var (
	_ caddy.Module      = (*DefenderAdmin)(nil)
	_ caddy.Provisioner = (*DefenderAdmin)(nil)
	_ caddy.App         = (*DefenderAdmin)(nil)
	_ caddy.AdminRouter = (*DefenderAdmin)(nil)
)
