package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyToolResultSeparatesFindingsFromExecution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tool string
		in   dto.ToolResult
		exec dto.ExecutionStatus
		find dto.FindingStatus
	}{
		{name: "sqlmap finding", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "Parameter: name (JSON) is vulnerable"}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "sqlmap clean", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "all tested parameters do not appear to be injectable"}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "tool failure", tool: "sqlmap_scan", in: dto.ToolResult{ReturnCode: 1, Stderr: "unable to connect"}, exec: dto.ExecutionFailed, find: dto.FindingsUnknown},
		{name: "timeout", tool: "nikto_scan", in: dto.ToolResult{TimedOut: true, PartialResults: true}, exec: dto.ExecutionTimedOut, find: dto.FindingsUnknown},
		{name: "whatweb internal error", tool: "whatweb_scan", in: dto.ToolResult{Success: true, Stdout: "ERROR Opening: target"}, exec: dto.ExecutionFailed, find: dto.FindingsUnknown},
		{name: "dalfox clean JSON", tool: "dalfox_scan", in: dto.ToolResult{Success: true, Stdout: `{"findings":[],"meta":{"findings_count":0}}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
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
