package fetchers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var testLogger = zap.NewNop()

func TestNewFileFetcher(t *testing.T) {
	t.Run("ValidFile", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write some test IPs
		content := "192.168.1.1\n10.0.0.0/8\n"
		_, err = tmpFile.WriteString(content)
		require.NoError(t, err)
		tmpFile.Close()

		// Create FileFetcher
		fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
		require.NoError(t, err)
		require.NotNil(t, fetcher)
		defer fetcher.Close()

		// Verify ranges loaded
		ranges, err := fetcher.FetchIPRanges()
		require.NoError(t, err)
		assert.Len(t, ranges, 2)
		assert.Contains(t, ranges, "192.168.1.1")
		assert.Contains(t, ranges, "10.0.0.0/8")
	})

	t.Run("EmptyFilePath", func(t *testing.T) {
		fetcher, err := NewFileFetcher("", testLogger, nil)
		assert.Error(t, err)
		assert.Nil(t, fetcher)
		assert.Contains(t, err.Error(), "file path cannot be empty")
	})

	t.Run("NonexistentFile", func(t *testing.T) {
		fetcher, err := NewFileFetcher("/nonexistent/file.txt", testLogger, nil)
		assert.Error(t, err)
		assert.Nil(t, fetcher)
	})
}

func TestFileFetcher_Name(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
	require.NoError(t, err)
	defer fetcher.Close()

	assert.Equal(t, "file", fetcher.Name())
}

func TestFileFetcher_Description(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
	require.NoError(t, err)
	defer fetcher.Close()

	desc := fetcher.Description()
	assert.Contains(t, desc, "IP ranges loaded from file")
	assert.Contains(t, desc, tmpFile.Name())
}

func TestFileFetcher_FetchIPRanges(t *testing.T) {
	t.Run("ValidContent", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := `# Comment line
192.168.1.1
10.0.0.0/8

# Another comment
172.16.0.0/12
2001:db8::/32
`
		_, err = tmpFile.WriteString(content)
		require.NoError(t, err)
		tmpFile.Close()

		fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
		require.NoError(t, err)
		defer fetcher.Close()

		ranges, err := fetcher.FetchIPRanges()
		require.NoError(t, err)
		assert.Len(t, ranges, 4)
		assert.Contains(t, ranges, "192.168.1.1")
		assert.Contains(t, ranges, "10.0.0.0/8")
		assert.Contains(t, ranges, "172.16.0.0/12")
		assert.Contains(t, ranges, "2001:db8::/32")
	})

	t.Run("EmptyFile", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
		require.NoError(t, err)
		defer fetcher.Close()

		ranges, err := fetcher.FetchIPRanges()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no IP ranges loaded")
		assert.Nil(t, ranges)
	})

	t.Run("OnlyCommentsAndEmptyLines", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := `# Just comments

# More comments

`
		_, err = tmpFile.WriteString(content)
		require.NoError(t, err)
		tmpFile.Close()

		fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
		require.NoError(t, err)
		defer fetcher.Close()

		ranges, err := fetcher.FetchIPRanges()
		assert.Error(t, err)
		assert.Nil(t, ranges)
	})

	t.Run("WithInvalidIPs", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Mix valid and invalid IPs
		content := `192.168.1.1
invalid-ip
10.0.0.0/8
999.999.999.999
172.16.0.0/12
not-an-ip
`
		_, err = tmpFile.WriteString(content)
		require.NoError(t, err)
		tmpFile.Close()

		fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
		require.NoError(t, err)
		defer fetcher.Close()

		// Should load only valid IPs
		ranges, err := fetcher.FetchIPRanges()
		require.NoError(t, err)
		assert.Len(t, ranges, 3) // Only the 3 valid entries
		assert.Contains(t, ranges, "192.168.1.1")
		assert.Contains(t, ranges, "10.0.0.0/8")
		assert.Contains(t, ranges, "172.16.0.0/12")
	})
}

func TestFileFetcher_validateIPOrCIDR(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
	require.NoError(t, err)
	defer fetcher.Close()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv4 CIDR", "10.0.0.0/8", false},
		{"Valid IPv6", "2001:db8::1", false},
		{"Valid IPv6 CIDR", "2001:db8::/32", false},
		{"Invalid IP", "invalid", true},
		{"Invalid CIDR", "192.168.1.0/33", true},
		{"Empty string", "", true},
		{"Random text", "hello world", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fetcher.validateIPOrCIDR(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFileFetcher_FileWatch(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "file-watch-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "blocklist.txt")

	// Create initial file
	err = os.WriteFile(tmpFile, []byte("192.168.1.1\n"), 0644)
	require.NoError(t, err)

	// Channel to track onChange calls
	changeChan := make(chan []string, 10)
	onChange := func(ranges []string) {
		changeChan <- ranges
	}

	// Create FileFetcher with onChange callback
	fetcher, err := NewFileFetcher(tmpFile, testLogger, onChange)
	require.NoError(t, err)
	defer fetcher.Close()

	// Verify initial load
	ranges, err := fetcher.FetchIPRanges()
	require.NoError(t, err)
	assert.Len(t, ranges, 1)
	assert.Contains(t, ranges, "192.168.1.1")

	// Modify the file
	time.Sleep(100 * time.Millisecond) // Small delay to ensure watcher is ready
	err = os.WriteFile(tmpFile, []byte("192.168.1.1\n10.0.0.0/8\n"), 0644)
	require.NoError(t, err)

	// Wait for file change notification
	select {
	case newRanges := <-changeChan:
		assert.Len(t, newRanges, 2)
		assert.Contains(t, newRanges, "192.168.1.1")
		assert.Contains(t, newRanges, "10.0.0.0/8")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for file change notification")
	}

	// Verify updated ranges
	ranges, err = fetcher.FetchIPRanges()
	require.NoError(t, err)
	assert.Len(t, ranges, 2)
}

func TestFileFetcher_Close(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
	require.NoError(t, err)

	// Close should not error
	err = fetcher.Close()
	assert.NoError(t, err)

	// Closing again should also not error
	err = fetcher.Close()
	assert.NoError(t, err)
}

func TestFileFetcher_ConcurrentAccess(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocklist-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	content := "192.168.1.1\n10.0.0.0/8\n"
	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)
	tmpFile.Close()

	fetcher, err := NewFileFetcher(tmpFile.Name(), testLogger, nil)
	require.NoError(t, err)
	defer fetcher.Close()

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			ranges, err := fetcher.FetchIPRanges()
			assert.NoError(t, err)
			assert.Len(t, ranges, 2)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
