package responders

import (
	"net/http"
	"os"
)

// FileResponder responds with a file and allows the user to specify headers.
type FileResponder struct {
	FilePath string
	Headers  map[string]string
}

func (f FileResponder) Respond(w http.ResponseWriter, r *http.Request) error {
	file, err := os.Open(f.FilePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return err
	}
	defer file.Close()

	for key, value := range f.Headers {
		w.Header().Set(key, value)
	}

	http.ServeContent(w, r, file.Name(), file.ModTime(), file)
	return nil
}
