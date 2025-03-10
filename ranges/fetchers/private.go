package fetchers

// PrivateFetcher implements the IPRangeFetcher interface for private network ranges.
type PrivateFetcher struct{}

func (f PrivateFetcher) Name() string {
	return "Private"
}
func (f PrivateFetcher) Description() string {
	return "Hardcoded IP ranges for private network ranges. Used in testing."
}
func (f PrivateFetcher) FetchIPRanges() ([]string, error) {
	return []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fd00::/8",
	}, nil
}
