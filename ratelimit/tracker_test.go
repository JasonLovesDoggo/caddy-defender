package ratelimit

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewTracker(t *testing.T) {
	config := Config{
		Enabled:            true,
		StatusCodes:        []int{404},
		MaxRequests:        10,
		WindowDuration:     5 * time.Minute,
		AutoAddToBlocklist: true,
		CleanupInterval:    10 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	if tracker == nil {
		t.Fatal("Expected tracker to be created")
	}

	if tracker.config.MaxRequests != 10 {
		t.Errorf("Expected MaxRequests to be 10, got %d", tracker.config.MaxRequests)
	}
}

func TestTrackRequest_Disabled(t *testing.T) {
	config := Config{
		Enabled: false,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")
	exceeded, err := tracker.TrackRequest(ip, 404)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if exceeded {
		t.Error("Expected exceeded to be false when disabled")
	}
}

func TestTrackRequest_IgnoreNonTrackedStatusCode(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404},
		MaxRequests:    5,
		WindowDuration: 1 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")

	// Track a 200 response (not in StatusCodes)
	exceeded, err := tracker.TrackRequest(ip, 200)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if exceeded {
		t.Error("Expected exceeded to be false for non-tracked status code")
	}

	// Verify no tracking data was created
	stats := tracker.GetStats()
	if len(stats) != 0 {
		t.Errorf("Expected no tracked IPs, got %d", len(stats))
	}
}

func TestTrackRequest_BelowThreshold(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404},
		MaxRequests:    5,
		WindowDuration: 1 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")

	// Track 3 requests (below threshold of 5)
	for i := 0; i < 3; i++ {
		exceeded, err := tracker.TrackRequest(ip, 404)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if exceeded {
			t.Errorf("Request %d should not exceed threshold", i+1)
		}
	}

	stats := tracker.GetStats()
	if len(stats) != 1 {
		t.Errorf("Expected 1 tracked IP, got %d", len(stats))
	}

	ipStats := stats[ip.String()]
	if ipStats.RequestCount != 3 {
		t.Errorf("Expected count to be 3, got %d", ipStats.RequestCount)
	}

	if ipStats.ExceedsThreshold {
		t.Error("Expected ExceedsThreshold to be false")
	}
}

func TestTrackRequest_ExceedThreshold(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404},
		MaxRequests:    5,
		WindowDuration: 1 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")

	// Track 6 requests (exceeds threshold of 5)
	var exceeded bool
	for i := 0; i < 6; i++ {
		var err error
		exceeded, err = tracker.TrackRequest(ip, 404)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	}

	if !exceeded {
		t.Error("Expected last request to exceed threshold")
	}

	stats := tracker.GetStats()
	ipStats := stats[ip.String()]
	if ipStats.RequestCount != 6 {
		t.Errorf("Expected count to be 6, got %d", ipStats.RequestCount)
	}

	if !ipStats.ExceedsThreshold {
		t.Error("Expected ExceedsThreshold to be true")
	}
}

func TestTrackRequest_WindowReset(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404},
		MaxRequests:    5,
		WindowDuration: 100 * time.Millisecond,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")

	// Track 3 requests
	for i := 0; i < 3; i++ {
		tracker.TrackRequest(ip, 404)
	}

	stats := tracker.GetStats()
	if stats[ip.String()].RequestCount != 3 {
		t.Errorf("Expected count to be 3, got %d", stats[ip.String()].RequestCount)
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Track another request (should reset window)
	tracker.TrackRequest(ip, 404)

	stats = tracker.GetStats()
	if stats[ip.String()].RequestCount != 1 {
		t.Errorf("Expected count to be reset to 1, got %d", stats[ip.String()].RequestCount)
	}
}

func TestTrackRequest_MultipleIPs(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404},
		MaxRequests:    5,
		WindowDuration: 1 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.101")
	ip3 := net.ParseIP("10.0.0.1")

	// Track different amounts for different IPs
	tracker.TrackRequest(ip1, 404)
	tracker.TrackRequest(ip1, 404)

	tracker.TrackRequest(ip2, 404)
	tracker.TrackRequest(ip2, 404)
	tracker.TrackRequest(ip2, 404)

	tracker.TrackRequest(ip3, 404)

	stats := tracker.GetStats()
	if len(stats) != 3 {
		t.Errorf("Expected 3 tracked IPs, got %d", len(stats))
	}

	if stats[ip1.String()].RequestCount != 2 {
		t.Errorf("Expected IP1 count to be 2, got %d", stats[ip1.String()].RequestCount)
	}

	if stats[ip2.String()].RequestCount != 3 {
		t.Errorf("Expected IP2 count to be 3, got %d", stats[ip2.String()].RequestCount)
	}

	if stats[ip3.String()].RequestCount != 1 {
		t.Errorf("Expected IP3 count to be 1, got %d", stats[ip3.String()].RequestCount)
	}
}

func TestTrackRequest_MultipleStatusCodes(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404, 403, 401},
		MaxRequests:    5,
		WindowDuration: 1 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")

	tracker.TrackRequest(ip, 404)
	tracker.TrackRequest(ip, 403)
	tracker.TrackRequest(ip, 401)
	tracker.TrackRequest(ip, 200) // Should not be tracked
	tracker.TrackRequest(ip, 404)

	stats := tracker.GetStats()
	if stats[ip.String()].RequestCount != 4 {
		t.Errorf("Expected count to be 4 (200 not tracked), got %d", stats[ip.String()].RequestCount)
	}
}

func TestResetIP(t *testing.T) {
	config := Config{
		Enabled:        true,
		StatusCodes:    []int{404},
		MaxRequests:    5,
		WindowDuration: 1 * time.Minute,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip := net.ParseIP("192.168.1.100")

	// Track some requests
	tracker.TrackRequest(ip, 404)
	tracker.TrackRequest(ip, 404)

	stats := tracker.GetStats()
	if len(stats) != 1 {
		t.Errorf("Expected 1 tracked IP, got %d", len(stats))
	}

	// Reset the IP
	reset := tracker.ResetIP(ip.String())
	if !reset {
		t.Error("Expected reset to return true")
	}

	stats = tracker.GetStats()
	if len(stats) != 0 {
		t.Errorf("Expected 0 tracked IPs after reset, got %d", len(stats))
	}

	// Try resetting non-existent IP
	reset = tracker.ResetIP("10.0.0.1")
	if reset {
		t.Error("Expected reset to return false for non-existent IP")
	}
}

func TestCleanup(t *testing.T) {
	config := Config{
		Enabled:         true,
		StatusCodes:     []int{404},
		MaxRequests:     5,
		WindowDuration:  50 * time.Millisecond,
		CleanupInterval: 100 * time.Millisecond,
	}

	logger := zap.NewNop()
	tracker := NewTracker(config, logger)
	defer tracker.Stop()

	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.101")

	// Track requests
	tracker.TrackRequest(ip1, 404)
	tracker.TrackRequest(ip2, 404)

	stats := tracker.GetStats()
	if len(stats) != 2 {
		t.Errorf("Expected 2 tracked IPs, got %d", len(stats))
	}

	// Wait for cleanup cycle (should remove entries older than 2x window = 100ms)
	time.Sleep(250 * time.Millisecond)

	stats = tracker.GetStats()
	if len(stats) != 0 {
		t.Errorf("Expected 0 tracked IPs after cleanup, got %d", len(stats))
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	config := Config{
		Enabled: true,
		// All other fields empty
	}

	config.ApplyDefaults()

	if len(config.StatusCodes) == 0 {
		t.Error("Expected StatusCodes to have defaults applied")
	}

	if config.StatusCodes[0] != 404 {
		t.Errorf("Expected default status code to be 404, got %d", config.StatusCodes[0])
	}

	if config.MaxRequests != 10 {
		t.Errorf("Expected default MaxRequests to be 10, got %d", config.MaxRequests)
	}

	if config.WindowDuration != 5*time.Minute {
		t.Errorf("Expected default WindowDuration to be 5m, got %v", config.WindowDuration)
	}

	if config.CleanupInterval != 10*time.Minute {
		t.Errorf("Expected default CleanupInterval to be 10m, got %v", config.CleanupInterval)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Enabled {
		t.Error("Expected default Enabled to be false (opt-in)")
	}

	if !config.AutoAddToBlocklist {
		t.Error("Expected default AutoAddToBlocklist to be true")
	}

	if config.MaxRequests != 10 {
		t.Errorf("Expected default MaxRequests to be 10, got %d", config.MaxRequests)
	}

	if config.WindowDuration != 5*time.Minute {
		t.Errorf("Expected default WindowDuration to be 5m, got %v", config.WindowDuration)
	}
}
