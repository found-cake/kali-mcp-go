package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyFeroxbusterIgnoresConfigurationAndStatisticsEvents(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("feroxbuster_scan", dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "{\"type\":\"configuration\",\"target_url\":\"https://example.test\"}\n{\"type\":\"statistics\",\"requests\":14}\n",
	})

	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsNotDetected {
		t.Fatalf("unexpected Feroxbuster classification: %+v", result)
	}
}

func TestClassifyFeroxbusterDetectsResponseEvent(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("feroxbuster_scan", dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "{\"type\":\"response\",\"url\":\"https://example.test/admin\",\"status\":200}\n{\"type\":\"statistics\",\"requests\":14}\n",
	})

	if result.FindingStatus != dto.FindingsDetected {
		t.Fatalf("unexpected Feroxbuster classification: %+v", result)
	}
}

func TestClassifyFeroxbusterReturnsUniqueStructuredDiscoveries(t *testing.T) {
	t.Parallel()

	// Given: Feroxbuster JSONL containing configuration, duplicate response, file response, and statistics events.
	result := dto.ToolResult{
		ReturnCode: 0,
		Stdout: "{\"type\":\"configuration\",\"target_url\":\"https://example.test\"}\n" +
			"{\"type\":\"response\",\"url\":\"https://example.test/admin\",\"status\":301,\"content_length\":0}\n" +
			"{\"type\":\"response\",\"url\":\"https://example.test/admin\",\"status\":301,\"content_length\":0,\"headers\":{\"location\":\"/admin/\"}}\n" +
			"{\"type\":\"response\",\"url\":\"https://example.test/app.js\",\"status\":200,\"content_length\":128}\n" +
			"{\"type\":\"statistics\",\"requests\":14}\n",
	}

	// When: the result is classified for MCP consumption.
	classified := classifyToolResult("feroxbuster_scan", result)

	// Then: only unique response events become structured discoveries.
	if len(classified.DiscoveredPaths) != 2 {
		t.Fatalf("unexpected Feroxbuster discoveries: %+v", classified.DiscoveredPaths)
	}
	if first := classified.DiscoveredPaths[0]; first.URL != "https://example.test/admin" || first.StatusCode != 301 || first.ResponseBytes != 0 || !first.Directory {
		t.Fatalf("unexpected directory discovery: %+v", first)
	}
	if second := classified.DiscoveredPaths[1]; second.URL != "https://example.test/app.js" || second.StatusCode != 200 || second.ResponseBytes != 128 || second.Directory {
		t.Fatalf("unexpected file discovery: %+v", second)
	}
}
