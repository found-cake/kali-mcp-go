package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyToolResultSeparatesFindingsFromExecution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tool        string
		in          dto.ToolResult
		exec        dto.ExecutionStatus
		find        dto.FindingStatus
		failureCode string
	}{
		{name: "sqlmap finding", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "Parameter: name (JSON) is vulnerable"}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "sqlmap clean", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "all tested parameters do not appear to be injectable"}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "tool failure", tool: "sqlmap_scan", in: dto.ToolResult{ReturnCode: 1, Stderr: "unable to connect"}, exec: dto.ExecutionFailed, find: dto.FindingsUnknown},
		{name: "partial failure", tool: "sqlmap_scan", in: dto.ToolResult{ReturnCode: 1, Stdout: "testing parameter id", PartialResults: true}, exec: dto.ExecutionFailed, find: dto.FindingsInconclusive},
		{name: "timeout", tool: "nikto_scan", in: dto.ToolResult{TimedOut: true, PartialResults: true}, exec: dto.ExecutionTimedOut, find: dto.FindingsInconclusive},
		{name: "cancelled", tool: "nuclei_scan", in: dto.ToolResult{Cancelled: true}, exec: dto.ExecutionCancelled, find: dto.FindingsInconclusive},
		{name: "whatweb internal error", tool: "whatweb_scan", in: dto.ToolResult{Success: true, Stdout: "ERROR Opening: target"}, exec: dto.ExecutionFailed, find: dto.FindingsInconclusive},
		{name: "dalfox clean JSON", tool: "dalfox_scan", in: dto.ToolResult{Success: true, Stdout: `{"findings":[],"meta":{"findings_count":0}}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "browser invalid JSON", tool: "browser_check", in: dto.ToolResult{Success: true, Stdout: `not-json`}, exec: dto.ExecutionFailed, find: dto.FindingsInconclusive, failureCode: "output_parse_failed"},
		{name: "retire clean JSON", tool: "retirejs_scan", in: dto.ToolResult{Success: true, Stdout: `{"version":"5.7.0","data":[]}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "osv finding exit one", tool: "osv_scan", in: dto.ToolResult{ReturnCode: 1, Stdout: `{"results":[{"packages":[]}]}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "osv clean JSON", tool: "osv_scan", in: dto.ToolResult{Success: true, Stdout: `{"results":[]}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyToolResult(test.tool, test.in)
			if got.ExecutionStatus != test.exec || got.FindingStatus != test.find {
				t.Fatalf("classification mismatch: %+v", got)
			}
			if got.Success != (got.ExecutionStatus == dto.ExecutionSucceeded) {
				t.Fatalf("success disagrees with execution status: %+v", got)
			}
			if got.ExecutionStatus != dto.ExecutionSucceeded && got.Failure == nil {
				t.Fatalf("expected structured failure metadata: %+v", got)
			}
			if got.ClassificationReason == "" {
				t.Fatalf("expected a machine-readable classification reason: %+v", got)
			}
			if test.failureCode != "" && (got.Failure == nil || got.Failure.Code != test.failureCode) {
				t.Fatalf("unexpected failure code: %+v", got.Failure)
			}
		})
	}
}

func TestTextResultReturnsStructuredContentAndMarksFailure(t *testing.T) {
	t.Parallel()

	input := &dto.ToolResult{ReturnCode: 2, Stderr: "execution failed"}
	callResult, structured, err := textResult("nmap_scan", input, nil)
	if err != nil {
		t.Fatalf("text result: %v", err)
	}
	if !callResult.IsError {
		t.Fatal("expected failed tool call to be marked as MCP error")
	}
	if structured.ExecutionStatus != dto.ExecutionFailed {
		t.Fatalf("expected structured failed status, got %+v", structured)
	}
}

func TestClassifyJWTResultExplainsMalformedInput(t *testing.T) {
	// Given: jwt_tool rejected a token that failed payload parsing before execution.
	input := dto.ToolResult{
		ReturnCode: 1,
		JWTAnalysis: &dto.JWTAnalysisMetadata{
			ParseStatus: dto.JWTMalformed, FailureStage: dto.JWTFailurePayloadJSON,
		},
	}

	// When: the MCP boundary classifies the tool result.
	result := classifyToolResult("jwt_analyze", input)

	// Then: execution failure and the parser failure stage remain distinct.
	if result.ExecutionStatus != dto.ExecutionFailed || result.FindingStatus != dto.FindingsUnknown || result.ClassificationReason != "jwt_payload_json_failed" {
		t.Fatalf("unexpected JWT classification: %+v", result)
	}
}
