package ratelimit

import (
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Tracker manages rate limiting based on HTTP status codes per IP address
type Tracker struct {
	config   Config
	storage  map[string]*RequestWindow
	mu       sync.RWMutex
	log      *zap.Logger
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// RequestWindow tracks requests within a time window using a fixed window counter
type RequestWindow struct {
	Count       int
	WindowStart time.Time
}

// NewTracker creates a new rate limit tracker
func NewTracker(config Config, log *zap.Logger) *Tracker {
	config.ApplyDefaults()

	t := &Tracker{
		config:   config,
		storage:  make(map[string]*RequestWindow),
		log:      log,
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	t.wg.Add(1)
	go t.cleanupLoop()

	t.log.Info("Rate limiter initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Ints("status_codes", config.StatusCodes),
		zap.Int("max_requests", config.MaxRequests),
		zap.Duration("window_duration", config.WindowDuration))

	return t
}

// TrackRequest tracks a request and returns true if the rate limit was exceeded
// This should be called AFTER the request has been processed to know the status code
func (t *Tracker) TrackRequest(clientIP net.IP, statusCode int) (exceeded bool, err error) {
	if !t.config.Enabled {
		return false, nil
	}

	// Check if this status code should be tracked
	if !t.shouldTrackStatus(statusCode) {
		return false, nil
	}

	ipStr := clientIP.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Get or create window for this IP
	window, exists := t.storage[ipStr]
	if !exists {
		window = &RequestWindow{
			Count:       1,
			WindowStart: now,
		}
		t.storage[ipStr] = window
		t.log.Debug("Started tracking IP",
			zap.String("ip", ipStr),
			zap.Int("status_code", statusCode))
		return false, nil
	}

	// Check if we need to reset the window
	if now.Sub(window.WindowStart) >= t.config.WindowDuration {
		window.Count = 1
		window.WindowStart = now
		t.log.Debug("Reset window for IP",
			zap.String("ip", ipStr),
			zap.Int("status_code", statusCode))
		return false, nil
	}

	// Increment counter
	window.Count++

	// Check if limit exceeded
	if window.Count > t.config.MaxRequests {
		t.log.Warn("Rate limit exceeded",
			zap.String("ip", ipStr),
			zap.Int("count", window.Count),
			zap.Int("max", t.config.MaxRequests),
			zap.Duration("window", t.config.WindowDuration),
			zap.Int("status_code", statusCode))
		return true, nil
	}

	t.log.Debug("Tracked request",
		zap.String("ip", ipStr),
		zap.Int("count", window.Count),
		zap.Int("max", t.config.MaxRequests),
		zap.Int("status_code", statusCode))

	return false, nil
}

// shouldTrackStatus checks if a status code should be tracked
func (t *Tracker) shouldTrackStatus(statusCode int) bool {
	for _, code := range t.config.StatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

// GetStats returns current tracking statistics
func (t *Tracker) GetStats() map[string]TrackedIP {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := make(map[string]TrackedIP, len(t.storage))
	now := time.Now()

	for ip, window := range t.storage {
		stats[ip] = TrackedIP{
			IP:               ip,
			RequestCount:     window.Count,
			WindowStart:      window.WindowStart,
			TimeRemaining:    t.config.WindowDuration - now.Sub(window.WindowStart),
			ExceedsThreshold: window.Count > t.config.MaxRequests,
		}
	}

	return stats
}

// TrackedIP represents statistics for a single IP address
type TrackedIP struct {
	IP               string        `json:"ip"`
	RequestCount     int           `json:"request_count"`
	WindowStart      time.Time     `json:"window_start"`
	TimeRemaining    time.Duration `json:"time_remaining"`
	ExceedsThreshold bool          `json:"exceeds_threshold"`
}

// cleanupLoop periodically removes old tracking entries
func (t *Tracker) cleanupLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(t.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.cleanup()
		case <-t.stopChan:
			return
		}
	}
}

// cleanup removes entries older than 2x the window duration
func (t *Tracker) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := t.config.WindowDuration * 2
	removed := 0

	for ip, window := range t.storage {
		if now.Sub(window.WindowStart) > cutoff {
			delete(t.storage, ip)
			removed++
		}
	}

	if removed > 0 {
		t.log.Debug("Cleaned up old rate limit entries",
			zap.Int("removed", removed),
			zap.Int("remaining", len(t.storage)))
	}
}

// Stop gracefully shuts down the tracker
func (t *Tracker) Stop() {
	close(t.stopChan)
	t.wg.Wait()
	t.log.Info("Rate limiter stopped")
}

// ResetIP clears tracking data for a specific IP
func (t *Tracker) ResetIP(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.storage[ip]; exists {
		delete(t.storage, ip)
		t.log.Info("Reset rate limit tracking for IP", zap.String("ip", ip))
		return true
	}
	return false
}
