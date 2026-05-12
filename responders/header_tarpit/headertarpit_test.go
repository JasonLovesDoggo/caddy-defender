package header_tarpit

import (
	"time"
)

// Helper function to create a new responder
func newTestResponder(content Content, timeout time.Duration) *Responder {
	return &Responder{
		Config: &Config{
			Content:        content,
			Timeout:        timeout,
			DelayPerSecond: 4,
			ResponseCode:   200,
		},
	}
}
