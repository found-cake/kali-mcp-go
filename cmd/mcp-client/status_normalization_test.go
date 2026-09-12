package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyNiktoInternalTimeoutKeepsProgressAndFindingIndependent(t *testing.T) {
	t.Parallel()

	// Given: Nikto exits zero after its own maximum time and reports a useful finding.
	result := dto.ToolResult{
		ReturnCode: 0,
		Stderr:     "Host maximum execution time of 90 seconds reached\n+ 500 requests: 2 item(s) reported",
		Progress:   &dto.ProgressMetadata{Phase: dto.ProgressCompleted},
	}

	// When: the result is normalized at the MCP boundary.
	classified := classifyToolResult("nikto_scan", result)

	// Then: execution is timed out while the partial finding remains detected.
	if classified.ExecutionStatus != dto.ExecutionTimedOut || classified.Status != dto.RunTimeout || classified.Progress.Phase != dto.ProgressTimedOut {
		t.Fatalf("Nikto timeout state is contradictory: %+v", classified)
	}
	if classified.Success || !classified.PartialResults || classified.FindingStatus != dto.FindingsDetected {
		t.Fatalf("Nikto partial finding was not preserved: %+v", classified)
	}
}
