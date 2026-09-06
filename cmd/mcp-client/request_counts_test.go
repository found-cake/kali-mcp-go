package main

import (
	"strings"
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

func TestClassifyNucleiTimeoutDoesNotExposeScheduledRequestsAsDelivered(t *testing.T) {
	t.Parallel()

	// Given: Nuclei scheduled forty requests before a timed-out scan delivered them all.
	result := dto.ToolResult{
		ReturnCode: -1,
		TimedOut:   true,
		Stderr:     "{\"duration\":\"0:00:05\",\"requests\":\"40\",\"startedAt\":\"2026-09-05T12:00:00Z\"}\n",
	}

	// When: the MCP client classifies the partial scan.
	classified := classifyToolResult("nuclei_scan", result)

	// Then: the runtime counter is preserved without claiming forty delivered HTTP requests.
	if classified.HTTPRequests != nil || classified.RequestCountSource != dto.RequestCountUnknown {
		t.Fatalf("scheduled requests were exposed as delivered: %+v", classified)
	}
	if classified.NucleiRuntime == nil || classified.NucleiRuntime.Requests != 40 || classified.NucleiRuntime.RequestsSemantics != dto.NucleiRequestsScheduled {
		t.Fatalf("Nuclei runtime semantics are missing: %+v", classified.NucleiRuntime)
	}
	if len(classified.Warnings) == 0 || !strings.Contains(classified.Warnings[0], "scheduled") {
		t.Fatalf("scheduled request warning is missing: %v", classified.Warnings)
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
