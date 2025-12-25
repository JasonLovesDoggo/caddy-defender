package fetchers

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
)

// HuaweiCloudFetcher implements the IPRangeFetcher interface for Huawei Cloud.
type HuaweiCloudFetcher struct{}

func (f HuaweiCloudFetcher) Name() string {
	return "huawei"
}

func (f HuaweiCloudFetcher) Description() string {
	return "Fetches IP ranges for Huawei Cloud services."
}

func (f HuaweiCloudFetcher) FetchIPRanges() ([]string, error) {
	const huaweiURL = "https://networksdb.io/ip-addresses-of/huawei-cloud"

	resp, err := http.Get(huaweiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Huawei Cloud IP ranges: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code from Huawei Cloud IP list: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Huawei Cloud response body: %v", err)
	}

	// Extract CIDR blocks using regex
	cidrRegex := regexp.MustCompile(`<b>CIDR:</b>\s*([^<]+)<br>`)
	matches := cidrRegex.FindAllStringSubmatch(string(body), -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("no CIDR blocks found in Huawei Cloud IP list")
	}

	ipRanges := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			cidr := match[1]
			// Skip entries marked as "N/A"
			if cidr != "N/A" {
				ipRanges = append(ipRanges, cidr)
			}
		}
	}

	return ipRanges, nil
}
