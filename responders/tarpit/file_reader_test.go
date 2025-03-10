package tarpit

import (
	"os"
	"testing"
)

func TestFileReader(t *testing.T) {
	t.Run("ValidFilePath", func(t *testing.T) {
		// Create a temporary file for testing
		file, err := os.CreateTemp("", "test_file")
		if err != nil {
			t.Errorf("Failed to create temporary file: %v", err)
		}

		t.Cleanup(func() {
			os.Remove(file.Name())
		})

		// Create a FileReader instance with the temp file path
		reader := FileReader{Path: file.Name()}

		t.Run("Validate", func(t *testing.T) {
			err := reader.Validate()
			if err != nil {
				t.Errorf("Expected no error from Validate, but got: %v", err)
			}
		})

		// Test Read method
		t.Run("Read", func(t *testing.T) {
			fileHandle, err := reader.Read()
			if err != nil {
				t.Errorf("Expected no error from Read, but got: %v", err)
			}
			defer fileHandle.Close()

			// Ensure the file handle is a valid ReadCloser
			if fileHandle == nil {
				t.Error("Expected a valid file handle from Read, but got nil")
			}
		})
	})

	t.Run("InvalidFilePath", func(t *testing.T) {
		// Create a FileReader instance with an invalid file path
		invalidPath := "/path/to/nonexistent/file"
		reader := FileReader{Path: invalidPath}

		// Test Validate method with an invalid file path
		t.Run("Validate", func(t *testing.T) {
			err := reader.Validate()
			if err == nil {
				t.Error("Expected error from Validate with invalid file path, but got none")
			}
		})

		// Test Read method with an invalid file path
		t.Run("Read", func(t *testing.T) {
			_, err := reader.Read()
			if err == nil {
				t.Error("Expected error from Read with invalid file path, but got none")
			}
		})
	})

	t.Run("EmptyFilePath", func(t *testing.T) {
		// Create a FileReader instance with an empty file path
		reader := FileReader{Path: ""}

		// Test Validate method with an empty file path
		t.Run("Validate", func(t *testing.T) {
			err := reader.Validate()
			if err == nil {
				t.Error("Expected error from Validate with empty file path, but got none")
			}
		})

		// Test Read method with an empty file path
		t.Run("Read", func(t *testing.T) {
			_, err := reader.Read()
			if err == nil {
				t.Error("Expected error from Read with empty file path, but got none")
			}
		})
	})
}
