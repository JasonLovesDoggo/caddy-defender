package useragent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var testLogger = zap.NewNop()

func TestUACheckerLiteralSignatures(t *testing.T) {
	checker := NewUAChecker([]string{"BadBot", "evil-crawler"}, testLogger)

	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{
			name:      "exact signature match",
			userAgent: "BadBot",
			expected:  true,
		},
		{
			name:      "substring match",
			userAgent: "Mozilla/5.0 (compatible; BadBot/1.0; +http://example.com)",
			expected:  true,
		},
		{
			name:      "case insensitive match",
			userAgent: "mozilla/5.0 (compatible; badbot/2.0)",
			expected:  true,
		},
		{
			name:      "second signature match",
			userAgent: "some evil-crawler build 3",
			expected:  true,
		},
		{
			name:      "normal browser not matched",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expected:  false,
		},
		{
			name:      "empty user agent not matched",
			userAgent: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, checker.Matches(tt.userAgent))
		})
	}
}

func TestUACheckerPredefinedGroup(t *testing.T) {
	checker := NewUAChecker([]string{"ai"}, testLogger)

	assert.True(t, checker.Matches("Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"))
	assert.True(t, checker.Matches("ClaudeBot/1.0 (+https://www.anthropic.com/claude-bot)"))
	assert.True(t, checker.Matches("CCBot/2.0 (https://commoncrawl.org/faq/)"))
	assert.False(t, checker.Matches("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"))
}

func TestUACheckerEmptyConfig(t *testing.T) {
	checker := NewUAChecker(nil, testLogger)
	assert.False(t, checker.Matches("GPTBot"))
	assert.False(t, checker.Matches("anything"))
}

func TestUACheckerMixedEntries(t *testing.T) {
	checker := NewUAChecker([]string{"ai", "InternalScanner"}, testLogger)
	assert.True(t, checker.Matches("GPTBot/1.1"))
	assert.True(t, checker.Matches("InternalScanner/9"))
	assert.False(t, checker.Matches("curl/8.0.1"))
}
