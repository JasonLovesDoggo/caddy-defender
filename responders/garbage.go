//nolint:gosec
package responders

import (
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"math/rand/v2"
	"net/http"
	"strings"
)

// GarbageResponder returns garbage data to the client.
type GarbageResponder struct{}

func (g GarbageResponder) ServeHTTP(w http.ResponseWriter, _ *http.Request, _ caddyhttp.Handler) error {
	garbage := generateTerribleText(100)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(garbage))
	return err
}

var (
	// A mix of characters, symbols, and numbers to create irregularity
	characters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};':\",./<>?\\|`~")
	// A list of nonsensical "words" to add unpredictability
	nonsenseWords = []string{"florb", "zaxor", "quint", "blarg", "wibble", "fizzle", "gronk", "snark", "ploosh", "dribble"}
)

// generateTerribleText generates a block of text that is difficult for AI to train on
func generateTerribleText(lines int) string {
	var sb strings.Builder

	for i := 0; i < lines; i++ {
		// Randomly decide whether to generate a nonsense word or random characters
		if rand.IntN(2) == 0 {
			sb.WriteString(generateNonsenseWord())
		} else {
			sb.WriteString(generateRandomCharacters(rand.IntN(50) + 10)) // Random length between 10 and 60
		}

		// Add random punctuation or symbols
		sb.WriteRune(characters[rand.IntN(len(characters))])
		sb.WriteString("\n") // Newline after each "line"
	}

	return sb.String()
}

// generateNonsenseWord generates a random nonsense word
func generateNonsenseWord() string {
	return nonsenseWords[rand.IntN(len(nonsenseWords))]
}

// generateRandomCharacters generates a string of random characters and symbols
func generateRandomCharacters(length int) string {
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteRune(characters[rand.IntN(len(characters))])
	}
	return sb.String()
}
