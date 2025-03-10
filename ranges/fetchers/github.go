package fetchers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GithubCopilotFetcher implements the IPRangeFetcher interface for GitHub Copilot.
type GithubCopilotFetcher struct{}

func (f GithubCopilotFetcher) Name() string {
	return "GithubCopilot"
}

func (f GithubCopilotFetcher) Description() string {
	return "Fetches IP ranges for GitHub Copilot services."
}

func (f GithubCopilotFetcher) FetchIPRanges() ([]string, error) {
	// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses
	resp, err := http.Get("https://api.github.com/meta")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub Copilot IP ranges: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from GitHub Copilot: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GitHub Copilot JSON: %v", err)
	}

	// Use the "copilot" key to get the IP ranges
	copilotValue, ok := result["copilot"]
	if !ok {
		return nil, fmt.Errorf("no 'copilot' key found in GitHub Copilot response")
	}

	// Convert the copilot value to a []interface{}
	copilotRangesInterface, ok := copilotValue.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type for 'copilot' key: expected []interface{}, got %T", copilotValue)
	}

	// Convert []interface{} to []string
	// pre-allocate to at least the current length of the slice.
	// assume it will grow to 1.3 times the current length, so pre-allocate to that size.
	var copilotRanges = make([]string, 0,
		int(float32(len(copilotRangesInterface))*1.3))

	for _, v := range copilotRangesInterface {
		ipRange, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected type in 'copilot' IP ranges: expected string, got %T", v)
		}
		copilotRanges = append(copilotRanges, ipRange)
	}

	return copilotRanges, nil
}
