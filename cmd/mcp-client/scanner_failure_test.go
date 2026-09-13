package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestScannerSemanticFailuresOverrideZeroExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tool        string
		result      dto.ToolResult
		failureCode string
	}{
		{
			name: "Nmap receives no valid targets", tool: "nmap_scan",
			result:      dto.ToolResult{ReturnCode: 0, Stdout: "Nmap done: 0 IP addresses (0 hosts up) scanned", Stderr: "WARNING: No targets were specified, so 0 hosts scanned."},
			failureCode: "nmap_no_targets",
		},
		{
			name: "Nuclei cannot execute any request", tool: "nuclei_scan",
			result:      dto.ToolResult{ReturnCode: 0, Stderr: `{"duration":"0:00:01","errors":"2","hosts":"1","matched":"0","percent":"100","requests":"1","startedAt":"2026-09-06T00:00:00Z","templates":"1","total":"1"}`},
			failureCode: "nuclei_requests_failed",
		},
		{
			name: "Nikto cannot connect", tool: "nikto_scan",
			result:      dto.ToolResult{ReturnCode: 0, Stdout: "+ [FAIL] Unable to connect to 127.0.0.1:1."},
			failureCode: "nikto_connection_failed",
		},
		{
			name: "Metasploit cannot load module", tool: "metasploit_run",
			result:      dto.ToolResult{ReturnCode: 0, Stdout: "[-] Failed to load module: exploit/missing"},
			failureCode: "metasploit_execution_failed",
		},
		{
			name: "Feroxbuster cannot reach a target", tool: "feroxbuster_scan",
			result:      dto.ToolResult{ReturnCode: 0, Stdout: `{"type":"statistics","requests":2,"errors":1,"initial_targets":0,"connection_errors":1}`, Stderr: "ERROR: Could not connect to any target provided"},
			failureCode: "feroxbuster_target_unreachable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := classifyToolResult(test.tool, test.result)

			if result.ExecutionStatus != dto.ExecutionFailed || result.FindingStatus != dto.FindingsInconclusive || !result.PartialResults {
				t.Fatalf("semantic failure classified as success: %+v", result)
			}
			if result.Failure == nil || result.Failure.Code != test.failureCode {
				t.Fatalf("failure code=%+v want=%s", result.Failure, test.failureCode)
			}
		})
	}
}

func TestNucleiPartialRequestErrorsRemainInconclusive(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("nuclei_scan", dto.ToolResult{
		ReturnCode: 0,
		Stdout:     `{"template-id":"confirmed-finding"}`,
		Stderr:     `{"duration":"0:00:01","errors":"1","hosts":"1","matched":"1","percent":"100","requests":"10","startedAt":"2026-09-06T00:00:00Z","templates":"1","total":"10"}`,
	})

	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsDetected || !result.PartialResults {
		t.Fatalf("partial Nuclei result lost finding or coverage state: %+v", result)
	}
	if result.NucleiRuntime == nil || result.NucleiRuntime.Requests != 10 || result.NucleiRuntime.Errors != 1 || result.NucleiRuntime.Matched != 1 {
		t.Fatalf("Nuclei runtime statistics were not preserved: %+v", result.NucleiRuntime)
	}
}

func TestFeroxbusterTimeoutPreservesReportedFinding(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("feroxbuster_scan", dto.ToolResult{
		TimedOut: true,
		Stdout: `{"type":"response","url":"https://example.test/admin","status":200}` + "\n" +
			`{"type":"statistics","requests":10,"errors":1,"initial_targets":1,"connection_errors":1}`,
	})

	if result.ExecutionStatus != dto.ExecutionTimedOut || result.FindingStatus != dto.FindingsDetected || !result.PartialResults {
		t.Fatalf("Feroxbuster timeout lost a reported finding: %+v", result)
	}
}
