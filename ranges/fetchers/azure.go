package fetchers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// AzurePublicCloudFetcher implements the IPRangeFetcher interface for Azure Public Cloud.
type AzurePublicCloudFetcher struct{}

func (f AzurePublicCloudFetcher) Name() string {
	return "AzurePublicCloud"
}

func (f AzurePublicCloudFetcher) Description() string {
	return "Fetches IP ranges for Azure Public Cloud services."
}

func (f AzurePublicCloudFetcher) FetchIPRanges() ([]string, error) {
	// Step 1: Fetch the download page to get the latest JSON URL
	downloadPageURL := "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
	resp, err := http.Get(downloadPageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Azure download page: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Azure download page body: %v", err)
	}

	// Step 2: Extract the JSON download URL using a regex
	urlRegex := regexp.MustCompile(`https://download\.microsoft\.com/[^\s"']+\.json`)
	matches := urlRegex.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return nil, fmt.Errorf("failed to find JSON download URL in Azure download page")
	}
	jsonDownloadURL := matches[0]

	// Step 3: Fetch the JSON file from the extracted URL
	resp, err = http.Get(jsonDownloadURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Azure Public Cloud IP ranges: %v", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from Azure Public Cloud: %v", err)
	}

	// Step 4: Parse the JSON and extract the IP ranges
	type AzureIPRanges struct {
		Values []struct {
			Name       string `json:"name"`
			Properties struct {
				Platform        string   `json:"platform"`
				SystemService   string   `json:"systemService"`
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}

	var ipRanges AzureIPRanges
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Azure Public Cloud JSON: %v", err)
	}

	// Step 5: Filter out the "Public" cloud IPs
	var publicIPs []string
	for _, value := range ipRanges.Values {
		if strings.EqualFold(value.Properties.Platform, "Azure") &&
			strings.EqualFold(value.Properties.SystemService, "ActionGroup") {
			publicIPs = append(publicIPs, value.Properties.AddressPrefixes...)
		}
	}

	return publicIPs, nil
}
