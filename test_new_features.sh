#!/bin/bash
# Test script for new file-based blocklist feature

echo "Testing FileFetcher..."
go test ./ranges/fetchers/... -v -run "TestFileFetcher"

echo ""
echo "Testing IPChecker.UpdateRanges..."
go test ./matchers/ip/... -v -run "TestIPChecker_UpdateRanges"

echo ""
echo "Running all tests..."
go test ./...
