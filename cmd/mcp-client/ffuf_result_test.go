package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyFFUFMissingKeywordAsExecutionFailure(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("ffuf_scan", dto.ToolResult{
		Success:    true,
		ReturnCode: 0,
		Stderr:     "Keyword FUZZ defined, but not found in headers, method, URL or POST data.",
	})

	if result.ExecutionStatus != dto.ExecutionFailed {
		t.Fatalf("ExecutionStatus = %q, want %q", result.ExecutionStatus, dto.ExecutionFailed)
	}
	if result.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("FindingStatus = %q, want %q", result.FindingStatus, dto.FindingsInconclusive)
	}
	if result.Success {
		t.Fatal("Success = true, want false")
	}
	if result.Failure == nil || result.Failure.Code != "invalid_fuzz_input" {
		t.Fatalf("Failure = %#v, want code invalid_fuzz_input", result.Failure)
	}
}

func TestClassifyFFUFTimeoutPreservesValidJSONFinding(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("ffuf_scan", dto.ToolResult{
		ReturnCode: -1,
		TimedOut:   true,
		Stdout:     `{"url":"https://example.test/admin","status":200}` + "\n",
	})

	if result.ExecutionStatus != dto.ExecutionTimedOut || result.FindingStatus != dto.FindingsDetected {
		t.Fatalf("execution=%q finding=%q, want timed_out/detected", result.ExecutionStatus, result.FindingStatus)
	}
	if !result.PartialResults || result.Success {
		t.Fatalf("partial=%t success=%t, want true/false", result.PartialResults, result.Success)
	}
	if result.ClassificationReason != "ffuf_partial_finding_reported" {
		t.Fatalf("ClassificationReason = %q", result.ClassificationReason)
	}
}

func TestClassifyFFUFTimeoutRejectsUnstructuredOutput(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("ffuf_scan", dto.ToolResult{
		ReturnCode: -1,
		TimedOut:   true,
		Stdout:     "Progress: 20 requests\n",
	})

	if result.ExecutionStatus != dto.ExecutionTimedOut || result.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("execution=%q finding=%q, want timed_out/inconclusive", result.ExecutionStatus, result.FindingStatus)
	}
}
