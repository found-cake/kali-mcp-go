package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyNucleiTimeoutPreservesValidPartialFinding(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("nuclei_scan", dto.ToolResult{
		ReturnCode: -1,
		TimedOut:   true,
		Stdout:     "{\"template-id\":\"exposed-metrics\",\"matched-at\":\"https://example.test/metrics\"}\n",
	})

	if result.ExecutionStatus != dto.ExecutionTimedOut || result.FindingStatus != dto.FindingsDetected {
		t.Fatalf("execution=%q finding=%q, want timed_out/detected", result.ExecutionStatus, result.FindingStatus)
	}
	if !result.PartialResults || result.Success {
		t.Fatalf("partial=%t success=%t, want true/false", result.PartialResults, result.Success)
	}
	if result.ClassificationReason != "nuclei_partial_finding_reported" {
		t.Fatalf("ClassificationReason = %q", result.ClassificationReason)
	}
}

func TestClassifyNucleiTimeoutRejectsNonFindingOutput(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("nuclei_scan", dto.ToolResult{
		ReturnCode: -1,
		TimedOut:   true,
		Stdout:     "[INF] Templates loaded for current scan: 42\n",
	})

	if result.ExecutionStatus != dto.ExecutionTimedOut || result.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("execution=%q finding=%q, want timed_out/inconclusive", result.ExecutionStatus, result.FindingStatus)
	}
}

func TestClassifyNucleiSuccessfulMalformedOutputIsInconclusive(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("nuclei_scan", dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "not nuclei JSONL",
	})

	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("execution=%q finding=%q, want succeeded/inconclusive", result.ExecutionStatus, result.FindingStatus)
	}
}

func TestClassifyNucleiSuccessfulDiagnosticOnlyOutputIsNotDetected(t *testing.T) {
	// Given: a successful Nuclei run whose stdout contains only a known diagnostic line.
	input := dto.ToolResult{
		ReturnCode:      0,
		ExecutionStatus: dto.ExecutionSucceeded,
		Stdout:          "[WRN] Loading 1 unsigned templates for scan. Use with caution.\n",
	}

	// When: the terminal finding status is classified.
	result := classifyToolResult("nuclei_scan", input)

	// Then: a diagnostic is not treated as malformed finding JSONL.
	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsNotDetected {
		t.Fatalf("unexpected diagnostic-only classification: %+v", result)
	}
	if result.ClassificationReason != "scanner_completed_without_output" {
		t.Fatalf("classification reason=%q", result.ClassificationReason)
	}
}
