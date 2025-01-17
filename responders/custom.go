package responders

import (
	"net/http"
)

// CustomResponder returns a custom response.
type CustomResponder struct {
	Message *string `json:"message"`
}

func (c CustomResponder) Respond(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(*c.Message))
	return err
}
