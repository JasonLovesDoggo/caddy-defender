package tarpit

import (
	"bytes"
	"io"
)

// TimeoutReader implements the ContentReader interface and holds the connection open for a specified Timeout.
type TimeoutReader struct{}

// Read implements the io.Reader interface and limits the reading to the specified Timeout.
func (n TimeoutReader) Read() (io.ReadCloser, error) {
	reader := bytes.NewReader([]byte{})

	dumbReader := &dumbReader{
		Reader: reader,
	}

	return dumbReader, nil
}

// Validate does nothing.
func (n TimeoutReader) Validate() error {
	return nil
}

// dumbReader wraps an io.Reader to implement the io.ReadCloser interface and does nothing else.
// This is simply to stall connections in the event no content is provided.
type dumbReader struct {
	Reader io.Reader
}

// Read implements the io.Reader interface.
func (t *dumbReader) Read(_ []byte) (n int, err error) {
	return 0, nil
}

// Close implements the io.Closer interface to close the underlying reader.
func (t *dumbReader) Close() error {
	return nil
}
