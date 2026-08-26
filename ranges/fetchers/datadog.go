package fetchers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

// DatadogFetcher implements the IPRangeFetcher interface for Datadog.
type DatadogFetcher struct{}

func (f DatadogFetcher) Name() string {
	return "Datadog"
}

func (f DatadogFetcher) Description() string {
	return "Fetches IP ranges used by Datadog services like the agent, APM, logs, and synthetics."
}

func (f DatadogFetcher) FetchIPRanges() ([]string, error) {
	// https://docs.datadoghq.com/api/latest/ip-ranges/
	const url = "https://ip-ranges.datadoghq.com/"

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Datadog IP ranges: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code from Datadog: %d", resp.StatusCode)
	}

	// The payload is keyed by service (agents, api, apm, logs, synthetics, ...)
	// alongside a couple of metadata fields (version, modified). Decode into raw
	// messages so new services get picked up automatically, and skip anything
	// that doesn't fit the prefixes shape.
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Datadog JSON: %v", err)
	}

	var ipRanges []string
	for _, raw := range payload {
		var prefixes struct {
			PrefixesIPv4 []string `json:"prefixes_ipv4"`
			PrefixesIPv6 []string `json:"prefixes_ipv6"`
		}
		if err := json.Unmarshal(raw, &prefixes); err != nil {
			// version and modified are not objects, so they land here.
			continue
		}
		ipRanges = append(ipRanges, prefixes.PrefixesIPv4...)
		ipRanges = append(ipRanges, prefixes.PrefixesIPv6...)
	}

	// Services overlap and map iteration order isn't stable, so sort for a
	// deterministic result and drop the duplicates that sorting makes adjacent.
	sort.Strings(ipRanges)
	unique := make([]string, 0, len(ipRanges))
	for i, r := range ipRanges {
		if i == 0 || r != ipRanges[i-1] {
			unique = append(unique, r)
		}
	}

	return unique, nil
}
