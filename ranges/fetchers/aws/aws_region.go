package aws

import "fmt"

// AWSRegionFetcher implements the IPRangeFetcher interface for AWS regions.
type AWSRegionFetcher struct {
	Region string // The AWS region to fetch IP ranges for
}

func (f AWSRegionFetcher) Name() string {
	return fmt.Sprintf("AWS-%s", f.Region)
}

func (f AWSRegionFetcher) Description() string {
	return fmt.Sprintf("Fetches IP ranges for AWS services in the %s region.", f.Region)
}

func (f AWSRegionFetcher) FetchIPRanges() ([]string, error) {
	// Fetch AWS IP ranges for the specified region
	return fetchAWSIPRanges(f.Region, "")
}