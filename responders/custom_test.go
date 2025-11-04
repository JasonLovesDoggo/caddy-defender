package responders

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomResponder_DefaultStatusCode(t *testing.T) {
	responder := CustomResponder{
		Message: "Custom message",
		// StatusCode not set, should default to 200
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, rec.Code)
	}

	expectedBody := "Custom message"
	if rec.Body.String() != expectedBody {
		t.Errorf("Expected body '%s', but got '%s'", expectedBody, rec.Body.String())
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected Content-Type 'text/plain', but got '%s'", contentType)
	}
}

func TestCustomResponder_CustomStatusCode403(t *testing.T) {
	responder := CustomResponder{
		Message:    "Access denied",
		StatusCode: http.StatusForbidden,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, but got %d", http.StatusForbidden, rec.Code)
	}

	expectedBody := "Access denied"
	if rec.Body.String() != expectedBody {
		t.Errorf("Expected body '%s', but got '%s'", expectedBody, rec.Body.String())
	}
}

func TestCustomResponder_CustomStatusCode404(t *testing.T) {
	responder := CustomResponder{
		Message:    "Page not found",
		StatusCode: http.StatusNotFound,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status code %d, but got %d", http.StatusNotFound, rec.Code)
	}

	expectedBody := "Page not found"
	if rec.Body.String() != expectedBody {
		t.Errorf("Expected body '%s', but got '%s'", expectedBody, rec.Body.String())
	}
}

func TestCustomResponder_CustomStatusCode451(t *testing.T) {
	responder := CustomResponder{
		Message:    "Unavailable for legal reasons",
		StatusCode: http.StatusUnavailableForLegalReasons,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusUnavailableForLegalReasons {
		t.Errorf("Expected status code %d, but got %d", http.StatusUnavailableForLegalReasons, rec.Code)
	}

	expectedBody := "Unavailable for legal reasons"
	if rec.Body.String() != expectedBody {
		t.Errorf("Expected body '%s', but got '%s'", expectedBody, rec.Body.String())
	}
}

func TestCustomResponder_CustomStatusCode503(t *testing.T) {
	responder := CustomResponder{
		Message:    "Service temporarily unavailable",
		StatusCode: http.StatusServiceUnavailable,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status code %d, but got %d", http.StatusServiceUnavailable, rec.Code)
	}

	expectedBody := "Service temporarily unavailable"
	if rec.Body.String() != expectedBody {
		t.Errorf("Expected body '%s', but got '%s'", expectedBody, rec.Body.String())
	}
}

func TestCustomResponder_CustomStatusCode200Explicit(t *testing.T) {
	// Test explicit 200 status code (default behavior but explicitly set)
	responder := CustomResponder{
		Message:    "OK - Request processed successfully",
		StatusCode: http.StatusOK,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, rec.Code)
	}

	expectedBody := "OK - Request processed successfully"
	if rec.Body.String() != expectedBody {
		t.Errorf("Expected body '%s', but got '%s'", expectedBody, rec.Body.String())
	}
}

func TestCustomResponder_EmptyMessage(t *testing.T) {
	responder := CustomResponder{
		Message:    "",
		StatusCode: http.StatusForbidden,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, but got %d", http.StatusForbidden, rec.Code)
	}

	if rec.Body.String() != "" {
		t.Errorf("Expected empty body, but got '%s'", rec.Body.String())
	}
}

func TestCustomResponder_MultilineMessage(t *testing.T) {
	message := "Line 1\nLine 2\nLine 3"
	responder := CustomResponder{
		Message:    message,
		StatusCode: http.StatusOK,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, rec.Code)
	}

	if rec.Body.String() != message {
		t.Errorf("Expected body '%s', but got '%s'", message, rec.Body.String())
	}
}

func TestCustomResponder_LongMessage(t *testing.T) {
	// Test with a longer message
	var buf bytes.Buffer
	for i := 0; i < 1000; i++ {
		buf.WriteString("This is a long message. ")
	}
	message := buf.String()

	responder := CustomResponder{
		Message:    message,
		StatusCode: http.StatusTeapot, // 418 - Just for fun
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	err := responder.ServeHTTP(rec, req, nil)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if rec.Code != http.StatusTeapot {
		t.Errorf("Expected status code %d, but got %d", http.StatusTeapot, rec.Code)
	}

	if rec.Body.String() != message {
		t.Errorf("Message mismatch. Expected length %d, got %d", len(message), len(rec.Body.String()))
	}
}

func TestCustomResponder_VariousStatusCodes(t *testing.T) {
	testCases := []struct {
		name       string
		message    string
		statusCode int
	}{
		{"BadRequest", "Bad request", http.StatusBadRequest},
		{"Unauthorized", "Unauthorized", http.StatusUnauthorized},
		{"PaymentRequired", "Payment required", http.StatusPaymentRequired},
		{"Forbidden", "Forbidden", http.StatusForbidden},
		{"NotFound", "Not found", http.StatusNotFound},
		{"MethodNotAllowed", "Method not allowed", http.StatusMethodNotAllowed},
		{"Gone", "Gone", http.StatusGone},
		{"TooManyRequests", "Too many requests", http.StatusTooManyRequests},
		{"InternalServerError", "Internal server error", http.StatusInternalServerError},
		{"NotImplemented", "Not implemented", http.StatusNotImplemented},
		{"BadGateway", "Bad gateway", http.StatusBadGateway},
		{"ServiceUnavailable", "Service unavailable", http.StatusServiceUnavailable},
		{"GatewayTimeout", "Gateway timeout", http.StatusGatewayTimeout},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			responder := CustomResponder{
				Message:    tc.message,
				StatusCode: tc.statusCode,
			}

			req := httptest.NewRequest("GET", "http://example.com", nil)
			rec := httptest.NewRecorder()

			err := responder.ServeHTTP(rec, req, nil)
			if err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}

			if rec.Code != tc.statusCode {
				t.Errorf("Expected status code %d, but got %d", tc.statusCode, rec.Code)
			}

			if rec.Body.String() != tc.message {
				t.Errorf("Expected body '%s', but got '%s'", tc.message, rec.Body.String())
			}
		})
	}
}

