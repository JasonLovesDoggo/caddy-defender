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

// Routes implements caddy.AdminRouter to add API endpoints
func (m *Defender) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/defender/blocklist",
			Handler: caddy.AdminHandlerFunc(m.handleBlocklist),
		},
		{
			Pattern: "/defender/blocklist/*",
			Handler: caddy.AdminHandlerFunc(m.handleBlocklistItem),
		},
		{
			Pattern: "/defender/stats",
			Handler: caddy.AdminHandlerFunc(m.handleStats),
		},
	}
}

// handleBlocklist handles GET and POST for /defender/blocklist
func (m *Defender) handleBlocklist(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		return m.handleGetBlocklist(w, r)
	case http.MethodPost:
		return m.handleAddToBlocklist(w, r)
	default:
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}
}

// handleGetBlocklist returns all dynamically blocked IPs
func (m *Defender) handleGetBlocklist(w http.ResponseWriter, r *http.Request) error {
	if m.dynamicBlocklist == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "dynamic blocklist not initialized",
		}
	}

	ips := m.dynamicBlocklist.List()

	response := map[string]interface{}{
		"count": len(ips),
		"ips":   ips,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleAddToBlocklist adds IPs to the dynamic blocklist
func (m *Defender) handleAddToBlocklist(w http.ResponseWriter, r *http.Request) error {
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

	m.dynamicBlocklist.Add(req.IPs...)

	// Update IPChecker with new ranges
	allRanges := append([]string{}, m.Ranges...)
	if m.BlocklistFile != "" {
		// Include file-based ranges if configured
		fileFetcher, ok := m.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			allRanges = append(allRanges, fileRanges...)
		}
	}
	allRanges = append(allRanges, m.dynamicBlocklist.List()...)
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
func (m *Defender) handleBlocklistItem(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodDelete {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	if m.dynamicBlocklist == nil {
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

	removed := m.dynamicBlocklist.Remove(ip)
	if !removed {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Message:    fmt.Sprintf("IP not found in blocklist: %s", ip),
		}
	}

	// Update IPChecker
	allRanges := append([]string{}, m.Ranges...)
	if m.BlocklistFile != "" {
		fileFetcher, ok := m.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			allRanges = append(allRanges, fileRanges...)
		}
	}
	allRanges = append(allRanges, m.dynamicBlocklist.List()...)
	m.ipChecker.UpdateRanges(allRanges)

	response := map[string]interface{}{
		"removed": ip,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// handleStats returns statistics about blocked requests
func (m *Defender) handleStats(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
	}

	dynamicCount := 0
	if m.dynamicBlocklist != nil {
		dynamicCount = len(m.dynamicBlocklist.List())
	}

	fileCount := 0
	if m.BlocklistFile != "" {
		fileFetcher, ok := m.fileFetcher.(interface{ FetchIPRanges() ([]string, error) })
		if ok {
			fileRanges, _ := fileFetcher.FetchIPRanges()
			fileCount = len(fileRanges)
		}
	}

	response := map[string]interface{}{
		"configured_ranges": m.Ranges,
		"blocklist_file":    m.BlocklistFile,
		"counts": map[string]int{
			"configured_ranges": len(m.Ranges),
			"file_ranges":       fileCount,
			"dynamic_ranges":    dynamicCount,
			"total":             len(m.Ranges) + fileCount + dynamicCount,
		},
		"responder": m.RawResponder,
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}
