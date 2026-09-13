package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyDirbResultReturnsStructuredDiscoveries(t *testing.T) {
	t.Parallel()

	// Given: Dirb reports one content response and one directory.
	result := dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "+ http://example.test/admin (CODE:200|SIZE:123)\n==> DIRECTORY: http://example.test/assets/\n",
	}

	// When: the result is classified for MCP consumption.
	classified := classifyToolResult("dirb_scan", result)

	// Then: discoveries are structured independently from raw stdout.
	if classified.FindingStatus != dto.FindingsDetected || len(classified.DiscoveredPaths) != 2 {
		t.Fatalf("Dirb discoveries were not classified: %+v", classified)
	}
	if classified.DiscoveredPaths[0].URL != "http://example.test/admin" || classified.DiscoveredPaths[0].StatusCode != 200 || classified.DiscoveredPaths[0].ResponseBytes != 123 {
		t.Fatalf("unexpected content discovery: %+v", classified.DiscoveredPaths[0])
	}
	if classified.DiscoveredPaths[1].URL != "http://example.test/assets/" || !classified.DiscoveredPaths[1].Directory {
		t.Fatalf("unexpected directory discovery: %+v", classified.DiscoveredPaths[1])
	}
}
