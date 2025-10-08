package caddydefender

import (
	"encoding/json"
	"fmt"
	"net/http"
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

func init() {
	caddy.RegisterModule(DefenderAdmin{})
}

// DefenderAdmin is an App module that provides admin API routes for managing Defender
type DefenderAdmin struct {
	ctx caddy.Context
	log *zap.Logger

	// Registry of all Defender instances by their address
	defenders map[string]*Defender
	mu        sync.RWMutex
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
	d.defenders = make(map[string]*Defender)

	// Set the global instance so Defender middleware can register
	globalAdminMu.Lock()
	globalDefenderAdmin = d
	globalAdminMu.Unlock()

	d.log.Info("DefenderAdmin provisioned - admin API routes will be available")

	return nil
}

// Start is called after all modules are provisioned
func (d *DefenderAdmin) Start() error {
	d.log.Info("DefenderAdmin started", zap.Int("registered_defenders", len(d.defenders)))
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

// RegisterDefender allows Defender middleware instances to register themselves
func (d *DefenderAdmin) RegisterDefender(id string, defender *Defender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.defenders[id] = defender
	d.log.Debug("Registered Defender instance", zap.String("id", id))
}

// UnregisterDefender removes a Defender instance from the registry
func (d *DefenderAdmin) UnregisterDefender(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.defenders, id)
	d.log.Debug("Unregistered Defender instance", zap.String("id", id))
}

// getDefender retrieves the first available Defender instance
func (d *DefenderAdmin) getDefender() *Defender {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Return the first defender instance we find
	for _, defender := range d.defenders {
		return defender
	}
	return nil
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

// handleGetBlocklist returns all blocked IPs from all sources
func (d *DefenderAdmin) handleGetBlocklist(w http.ResponseWriter, r *http.Request, m *Defender) error {
	if m.dynamicBlocklist == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "dynamic blocklist not initialized",
		}
	}

	// Collect all blocked IPs from different sources
	allIPs := make(map[string]string) // map[ip]source

	// 1. Get file-based ranges
	var fileRanges []string
	if m.BlocklistFile != "" {
		fileFetcher, ok := m.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
		if ok {
			fileRanges, _ = fileFetcher.FetchIPRanges()
			for _, ip := range fileRanges {
				allIPs[ip] = "file"
			}
		}
	}

	// 2. Get dynamically added IPs
	dynamicIPs := m.dynamicBlocklist.List()
	for _, ip := range dynamicIPs {
		allIPs[ip] = "dynamic"
	}

	// Build response with categorized IPs
	response := map[string]interface{}{
		"total": len(allIPs),
		"sources": map[string]interface{}{
			"file":    len(fileRanges),
			"dynamic": len(dynamicIPs),
		},
		"ips": func() []map[string]string {
			result := make([]map[string]string, 0, len(allIPs))
			for ip, source := range allIPs {
				result = append(result, map[string]string{
					"ip":     ip,
					"source": source,
				})
			}
			return result
		}(),
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleAddToBlocklist adds IPs to the dynamic blocklist
func (d *DefenderAdmin) handleAddToBlocklist(w http.ResponseWriter, r *http.Request, m *Defender) error {
	if m.dynamicBlocklist == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "dynamic blocklist not initialized",
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

	if err := m.dynamicBlocklist.Add(req.IPs...); err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to add IPs to blocklist: %v", err),
		}
	}

	// Update IPChecker with new ranges
	// Note: if file persistence is enabled, the file watcher will trigger an update
	// Otherwise, we need to manually update with dynamic IPs
	allRanges := append([]string{}, m.Ranges...)
	if m.BlocklistFile != "" {
		// File persistence enabled - reload from file (which now includes dynamic IPs)
		fileFetcher, ok := m.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			allRanges = append(allRanges, fileRanges...)
		}
	} else {
		// No file persistence - add dynamic IPs directly
		allRanges = append(allRanges, m.dynamicBlocklist.List()...)
	}
	m.ipChecker.UpdateRanges(allRanges)

	response := map[string]interface{}{
		"added": req.IPs,
		"count": len(req.IPs),
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

	if defender.dynamicBlocklist == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "dynamic blocklist not initialized",
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

	removed, err := defender.dynamicBlocklist.Remove(ip)
	if err != nil {
		return caddy.APIError{
			HTTPStatus: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to remove IP from blocklist: %v", err),
		}
	}
	if !removed {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Message:    fmt.Sprintf("IP not found in blocklist: %s", ip),
		}
	}

	// Update IPChecker
	// Note: if file persistence is enabled, the file watcher will trigger an update
	// Otherwise, we need to manually update with dynamic IPs
	allRanges := append([]string{}, defender.Ranges...)
	if defender.BlocklistFile != "" {
		// File persistence enabled - reload from file (which now excludes removed IP)
		fileFetcher, ok := defender.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			allRanges = append(allRanges, fileRanges...)
		}
	} else {
		// No file persistence - add dynamic IPs directly
		allRanges = append(allRanges, defender.dynamicBlocklist.List()...)
	}
	defender.ipChecker.UpdateRanges(allRanges)

	response := map[string]interface{}{
		"removed": ip,
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

	dynamicCount := 0
	if defender.dynamicBlocklist != nil {
		dynamicCount = len(defender.dynamicBlocklist.List())
	}

	fileCount := 0
	if defender.BlocklistFile != "" {
		fileFetcher, ok := defender.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
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
			"dynamic_ranges":    dynamicCount,
			"total":             len(defender.Ranges) + fileCount + dynamicCount,
		},
		"responder": defender.RawResponder,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// Interface guards
var (
	_ caddy.Module      = (*DefenderAdmin)(nil)
	_ caddy.Provisioner = (*DefenderAdmin)(nil)
	_ caddy.App         = (*DefenderAdmin)(nil)
	_ caddy.AdminRouter = (*DefenderAdmin)(nil)
)
