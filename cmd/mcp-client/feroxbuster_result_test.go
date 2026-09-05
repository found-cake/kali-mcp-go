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
