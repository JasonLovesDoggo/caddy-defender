// Package useragent provides matching of HTTP User-Agent headers against a
// list of bad bot and AI crawler signatures. It mirrors the IP matcher: a
// configured entry is either a predefined group key (expanded to a bundled
// list of signatures) or a literal signature to match directly.
package useragent

import (
	"strings"

	"go.uber.org/zap"
)

// PredefinedUserAgents maps a group key to a list of User-Agent signatures.
// Signatures are matched case-insensitively as substrings of the request
// User-Agent header. The lists are intentionally conservative and cover the
// most common AI crawlers and scrapers.
var PredefinedUserAgents = map[string][]string{
	// "ai" covers well known AI/LLM crawlers and dataset scrapers.
	"ai": {
		"GPTBot",
		"ChatGPT-User",
		"OAI-SearchBot",
		"ClaudeBot",
		"Claude-Web",
		"anthropic-ai",
		"CCBot",
		"Google-Extended",
		"GoogleOther",
		"PerplexityBot",
		"Perplexity-User",
		"Amazonbot",
		"Applebot-Extended",
		"Bytespider",
		"Diffbot",
		"FacebookBot",
		"meta-externalagent",
		"ImagesiftBot",
		"Omgili",
		"Omgilibot",
		"YouBot",
		"cohere-ai",
		"Timpibot",
	},
}

// UAChecker matches request User-Agent headers against configured signatures.
type UAChecker struct {
	// signatures holds lowercased substrings to match against.
	signatures []string
	log        *zap.Logger
}

// NewUAChecker builds a checker from a list of entries. Each entry is either a
// predefined group key (expanded via PredefinedUserAgents) or a literal
// signature. An empty list produces a checker that never matches, keeping
// User-Agent filtering opt-in.
func NewUAChecker(entries []string, log *zap.Logger) *UAChecker {
	c := &UAChecker{log: log}
	for _, entry := range entries {
		if group, ok := PredefinedUserAgents[entry]; ok {
			for _, sig := range group {
				c.add(sig)
			}
			continue
		}
		c.add(entry)
	}
	return c
}

func (c *UAChecker) add(sig string) {
	sig = strings.ToLower(strings.TrimSpace(sig))
	if sig == "" {
		return
	}
	c.signatures = append(c.signatures, sig)
}

// Matches reports whether the given User-Agent header contains any configured
// signature (case-insensitive substring match). It always returns false when
// no signatures are configured or the header is empty.
func (c *UAChecker) Matches(userAgent string) bool {
	if len(c.signatures) == 0 || userAgent == "" {
		return false
	}
	ua := strings.ToLower(userAgent)
	for _, sig := range c.signatures {
		if strings.Contains(ua, sig) {
			return true
		}
	}
	return false
}
