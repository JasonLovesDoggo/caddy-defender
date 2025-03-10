package tarpit

import (
	"testing"
)

func TestTimeoutReader(t *testing.T) {
	t.Run("Read", func(t *testing.T) {
		timeoutReader := TimeoutReader{}

		reader, err := timeoutReader.Read()
		if err != nil {
			t.Errorf("Expected no error from Read, but got: %v", err)
		}

		// Check that the returned reader is not nil
		if reader == nil {
			t.Error("Expected non-nil ReadCloser from Read, but got nil")
		}

		// Check if the reader is of type *dumbReader
		_, ok := reader.(*dumbReader)
		if !ok {
			t.Error("Expected *dumbReader type from Read, but got a different type")
		}
	})

	t.Run("Validate", func(t *testing.T) {
		timeoutReader := TimeoutReader{}

		err := timeoutReader.Validate()
		if err != nil {
			t.Errorf("Expected no error from Validate, but got: %v", err)
		}
	})

	t.Run("dumbReaderRead", func(t *testing.T) {
		timeoutReader := TimeoutReader{}

		reader, err := timeoutReader.Read()
		if err != nil {
			t.Errorf("Expected no error from Read, but got: %v", err)
		}

		dumbReader, ok := reader.(*dumbReader)
		if !ok {
			t.Error("Expected *dumbReader type, but got a different type")
		}

		buf := make([]byte, 10)
		n, err := dumbReader.Read(buf)
		if n != 0 {
			t.Errorf("Expected Read to return 0 bytes, but got %d", n)
		}
		if err != nil {
			t.Errorf("Expected Read to return nil error, but got: %v", err)
		}
	})

	t.Run("dumbReaderClose", func(t *testing.T) {
		timeoutReader := TimeoutReader{}

		reader, err := timeoutReader.Read()
		if err != nil {
			t.Errorf("Expected no error from Read, but got: %v", err)
		}

		dumbReader, ok := reader.(*dumbReader)
		if !ok {
			t.Error("Expected *dumbReader type, but got a different type")
		}

		err = dumbReader.Close()
		if err != nil {
			t.Errorf("Expected no error from Close, but got: %v", err)
		}
	})
}
