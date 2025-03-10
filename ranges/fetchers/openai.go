package fetchers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OpenAIFetcher implements the IPRangeFetcher interface for OpenAI.
type OpenAIFetcher struct{}

func (f OpenAIFetcher) Name() string {
	return "OpenAI"
}
func (f OpenAIFetcher) Description() string {
	return "Fetches IP ranges for OpenAI services like ChatGPT, GPTBot, and SearchBot."
}
func (f OpenAIFetcher) FetchIPRanges() ([]string, error) {
	// https://platform.openai.com/docs/bots/overview-of-openai-crawlers
	urls := []string{
		"https://openai.com/searchbot.json",
		"https://openai.com/chatgpt-user.json",
		"https://openai.com/gptbot.json",
	}

	var allRanges []string
	for _, url := range urls {
		ranges, err := fetchOpenAIIPRanges(url)
		if err != nil {
			return nil, err
		}
		allRanges = append(allRanges, ranges...)
	}

	return allRanges, nil
}

type OpenAIIPRanges struct {
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
	} `json:"prefixes"`
}

func fetchOpenAIIPRanges(url string) ([]string, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP ranges from %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from %s: %v", url, err)
	}

	var ipRanges OpenAIIPRanges
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON from %s: %v", url, err)
	}

	var ranges []string
	for _, prefix := range ipRanges.Prefixes {
		if prefix.IPv4Prefix != "" {
			ranges = append(ranges, prefix.IPv4Prefix)
		}
	}

	return ranges, nil
}
