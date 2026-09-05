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
