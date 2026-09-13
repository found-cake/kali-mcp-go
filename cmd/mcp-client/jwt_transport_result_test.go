package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyJWTLiveTransportErrorsAsFailures(t *testing.T) {
	t.Parallel()

	for _, message := range []string{
		"ProxyError: Unable to connect to proxy",
		"NameResolutionError: Failed to resolve 'example.invalid'",
		"ConnectionError: Failed to establish a new connection",
	} {
		result := classifyToolResult("jwt_analyze", dto.ToolResult{
			ReturnCode: 0,
			Stderr:     message,
			Execution: dto.ExecutionMetadata{
				ArgvRedacted: []string{"jwt_tool", "[REDACTED]", "-t", "https://example.invalid/me", "-np"},
			},
			JWTAnalysis: &dto.JWTAnalysisMetadata{ParseStatus: dto.JWTParsed},
		})

		if result.ExecutionStatus != dto.ExecutionFailed || result.FindingStatus != dto.FindingsInconclusive {
			t.Fatalf("message %q classified as execution=%q finding=%q", message, result.ExecutionStatus, result.FindingStatus)
		}
		if result.Failure == nil || result.Failure.Code != "jwt_live_transport_failed" {
			t.Fatalf("message %q failure = %#v", message, result.Failure)
		}
		if result.Success || !result.PartialResults {
			t.Fatalf("message %q success=%t partial=%t", message, result.Success, result.PartialResults)
		}
	}
}

func TestJWTTransportTextDoesNotFailOfflineAnalysis(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("jwt_analyze", dto.ToolResult{
		ReturnCode:  0,
		Stderr:      "ProxyError appears in an offline diagnostic",
		JWTAnalysis: &dto.JWTAnalysisMetadata{ParseStatus: dto.JWTParsed},
	})
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		t.Fatalf("ExecutionStatus = %q, want %q", result.ExecutionStatus, dto.ExecutionSucceeded)
	}
}
