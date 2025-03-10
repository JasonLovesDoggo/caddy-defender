package tarpit

import (
	"io"
	"os"
)

// FileReader implements the ContentReader interface and reads files on disk.
type FileReader struct {
	Path string
}

// Read opens a file for streaming.
func (f FileReader) Read() (io.ReadCloser, error) {
	return os.Open(f.Path) // Returns a file handle for streaming
}

// Validate ensures the content path is readable
func (f FileReader) Validate() error {
	file, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}
