package fetchers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// FileFetcher implements IPRangeFetcher for loading IP addresses from a file.
// It supports automatic reloading when the file changes.
type FileFetcher struct {
	watcher  *fsnotify.Watcher
	log      *zap.Logger
	onChange func([]string) // Callback when ranges are updated
	ranges   []string
	mu       sync.RWMutex
	filePath string
}

// NewFileFetcher creates a new FileFetcher with file watching capability
func NewFileFetcher(filePath string, log *zap.Logger, onChange func([]string)) (*FileFetcher, error) {
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	f := &FileFetcher{
		filePath: filePath,
		watcher:  watcher,
		log:      log,
		onChange: onChange,
	}

	// Initial load
	if err := f.loadRanges(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to load initial ranges: %w", err)
	}

	// Start watching the file
	if err := f.startWatching(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to start watching file: %w", err)
	}

	return f, nil
}

// Name returns the name identifier for this fetcher
func (f *FileFetcher) Name() string {
	return "file"
}

// Description returns a description of this fetcher
func (f *FileFetcher) Description() string {
	return fmt.Sprintf("IP ranges loaded from file: %s", f.filePath)
}

// FetchIPRanges returns the current IP ranges loaded from the file
func (f *FileFetcher) FetchIPRanges() ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(f.ranges) == 0 {
		return nil, fmt.Errorf("no IP ranges loaded from file: %s", f.filePath)
	}

	// Return a copy to prevent external modifications
	result := make([]string, len(f.ranges))
	copy(result, f.ranges)
	return result, nil
}

// loadRanges reads IP addresses/ranges from the file
func (f *FileFetcher) loadRanges() error {
	file, err := os.Open(f.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var ranges []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate the IP/CIDR format
		if err := f.validateIPOrCIDR(line); err != nil {
			f.log.Warn("Invalid IP/CIDR in file",
				zap.String("file", f.filePath),
				zap.Int("line", lineNum),
				zap.String("value", line),
				zap.Error(err))
			continue
		}

		ranges = append(ranges, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	f.mu.Lock()
	f.ranges = ranges
	f.mu.Unlock()

	f.log.Info("Loaded IP ranges from file",
		zap.String("file", f.filePath),
		zap.Int("count", len(ranges)))

	return nil
}

// validateIPOrCIDR validates that the string is either a valid IP address or CIDR range
func (f *FileFetcher) validateIPOrCIDR(s string) error {
	// Try parsing as CIDR first
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}

	// Try parsing as IP address
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}

	return fmt.Errorf("invalid IP address or CIDR range: %q", s)
}

// startWatching begins monitoring the file for changes
func (f *FileFetcher) startWatching() error {
	if err := f.watcher.Add(f.filePath); err != nil {
		return fmt.Errorf("failed to watch file: %w", err)
	}

	go f.watchLoop()
	f.log.Info("Started watching file for changes", zap.String("file", f.filePath))

	return nil
}

// watchLoop handles file change events
func (f *FileFetcher) watchLoop() {
	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return
			}

			// Reload on write or create events
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				f.log.Info("File changed, reloading IP ranges",
					zap.String("file", f.filePath),
					zap.String("event", event.Op.String()))

				if err := f.loadRanges(); err != nil {
					f.log.Error("Failed to reload IP ranges",
						zap.String("file", f.filePath),
						zap.Error(err))
					continue
				}

				// Notify about the change
				if f.onChange != nil {
					f.mu.RLock()
					rangesCopy := make([]string, len(f.ranges))
					copy(rangesCopy, f.ranges)
					f.mu.RUnlock()

					f.onChange(rangesCopy)
				}
			}

		case err, ok := <-f.watcher.Errors:
			if !ok {
				return
			}
			f.log.Error("File watcher error",
				zap.String("file", f.filePath),
				zap.Error(err))
		}
	}
}

// Close stops watching the file and cleans up resources
func (f *FileFetcher) Close() error {
	if f.watcher != nil {
		return f.watcher.Close()
	}
	return nil
}
