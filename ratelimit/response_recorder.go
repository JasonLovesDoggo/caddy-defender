package ratelimit

import (
	"bufio"
	"net"
	"net/http"
)

// ResponseRecorder wraps http.ResponseWriter to capture the status code
type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
	Written    bool
}

// NewResponseRecorder creates a new ResponseRecorder
func NewResponseRecorder(w http.ResponseWriter) *ResponseRecorder {
	return &ResponseRecorder{
		ResponseWriter: w,
		StatusCode:     http.StatusOK, // Default status code
		Written:        false,
	}
}

// WriteHeader captures the status code
func (r *ResponseRecorder) WriteHeader(statusCode int) {
	if !r.Written {
		r.StatusCode = statusCode
		r.Written = true
	}
	r.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures status code is captured even if WriteHeader isn't called explicitly
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	if !r.Written {
		r.StatusCode = http.StatusOK
		r.Written = true
	}
	return r.ResponseWriter.Write(b)
}

// Hijack implements http.Hijacker interface if underlying writer supports it
func (r *ResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush implements http.Flusher interface if underlying writer supports it
func (r *ResponseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
