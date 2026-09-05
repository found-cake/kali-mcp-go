package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyNucleiResultParsesExactStatisticsCount(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("nuclei_scan", dto.ToolResult{
		ReturnCode: 0,
		Stderr:     "{\"duration\":\"0:00:01\",\"requests\":\"4\",\"startedAt\":\"2026-09-05T12:00:00Z\"}\n{\"duration\":\"0:00:02\",\"requests\":\"7\",\"startedAt\":\"2026-09-05T12:00:00Z\"}\n",
	})

	if result.HTTPRequests == nil || *result.HTTPRequests != 7 || result.RequestCountSource != dto.RequestCountParsed {
		t.Fatalf("Nuclei request count was not parsed: %+v", result)
	}
}

func TestClassifyFeroxbusterResultParsesExactStatisticsCount(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("feroxbuster_scan", dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "{\"type\":\"response\",\"url\":\"https://example.test/admin\"}\n{\"type\":\"statistics\",\"requests\":14,\"successes\":14}\n",
	})

	if result.HTTPRequests == nil || *result.HTTPRequests != 14 || result.RequestCountSource != dto.RequestCountParsed {
		t.Fatalf("Feroxbuster request count was not parsed: %+v", result)
	}
}

func TestClassifyFFUFResultDoesNotEstimateRequestCountFromFindingPosition(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("ffuf_scan", dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "{\"url\":\"https://example.test/admin\",\"position\":99,\"status\":200}\n",
	})

	if result.HTTPRequests != nil || result.RequestCountSource != dto.RequestCountUnknown {
		t.Fatalf("FFUF request count should remain unknown: %+v", result)
	}
}
