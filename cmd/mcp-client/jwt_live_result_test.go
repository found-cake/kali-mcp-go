package main

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyJWTLiveCompletedRejectedMutationsAsNotDetected(t *testing.T) {
	// Given: a completed live scan whose accepted baseline is followed only by rejected controls and mutations.
	input := dto.ToolResult{
		ReturnCode: 0,
		Execution: dto.ExecutionMetadata{
			ArgvRedacted: []string{"[REDACTED]", "-t", "https://example.test/me", "-np", "-cv", "accepted-canary", "-M", "er"},
		},
		JWTAnalysis: &dto.JWTAnalysisMetadata{ParseStatus: dto.JWTParsed},
		Stdout: `[+] FOUND "accepted-canary" in response:
jwttool_base Sending token Response Code: 200, 15 bytes
[+] FOUND "accepted-canary" in response:
jwttool_original Prescan: original token Response Code: 200, 15 bytes
jwttool_none Prescan: no token Response Code: 401, 8 bytes
jwttool_broken Prescan: Broken signature Response Code: 401, 8 bytes
[+] FOUND "accepted-canary" in response:
jwttool_repeat Prescan: repeat original token Response Code: 200, 15 bytes
LAUNCHING SCAN: Forced Errors
jwttool_first Injected None into Header Claim: alg Response Code: 401, 8 bytes
jwttool_second Injected True into Payload Claim: sub Response Code: 403, 8 bytes
Scanning mode completed: review the above results.
`,
	}

	// When: the common MCP result classifier analyzes the live transcript.
	result := classifyToolResult("jwt_analyze", input)

	// Then: the exact request counts and the completed negative verdict are structured.
	if result.FindingStatus != dto.FindingsNotDetected || result.ClassificationReason != "jwt_live_mutations_rejected" {
		t.Fatalf("unexpected JWT finding classification: %+v", result)
	}
	if result.HTTPRequests == nil || *result.HTTPRequests != 7 || result.RequestCountSource != dto.RequestCountParsed {
		t.Fatalf("JWT live request count was not parsed: %+v", result)
	}
	live := result.JWTLiveAnalysis
	if live == nil || !live.Completed || !live.BaselineAccepted || live.BaselineRequests != 3 || live.ControlsTested != 2 || live.ControlsRejected != 2 || live.MutationsTested != 2 || live.MutationsRejected != 2 || live.MutationsAccepted != 0 || live.MutationsInconclusive != 0 {
		t.Fatalf("unexpected JWT live analysis: %+v", live)
	}
}

func TestClassifyJWTLiveCanaryAcceptedMutationAsDetected(t *testing.T) {
	// Given: a completed live scan where a mutation receives the configured acceptance canary.
	input := dto.ToolResult{
		ReturnCode: 0,
		Execution: dto.ExecutionMetadata{
			ArgvRedacted: []string{"[REDACTED]", "-t", "https://example.test/me", "-cv", "accepted-canary", "-M", "er"},
		},
		JWTAnalysis: &dto.JWTAnalysisMetadata{ParseStatus: dto.JWTParsed},
		Stdout: `[+] FOUND "accepted-canary" in response:
jwttool_original Prescan: original token Response Code: 200, 15 bytes
LAUNCHING SCAN: Forced Errors
[+] FOUND "accepted-canary" in response:
jwttool_mutated Injected None into Header Claim: alg Response Code: 200, 15 bytes
Scanning mode completed: review the above results.
`,
	}

	// When: the result is classified.
	result := classifyToolResult("jwt_analyze", input)

	// Then: canary-confirmed mutation acceptance is a detected authentication finding.
	if result.FindingStatus != dto.FindingsDetected || result.ClassificationReason != "jwt_live_mutation_accepted" {
		t.Fatalf("unexpected accepted-mutation classification: %+v", result)
	}
	if result.JWTLiveAnalysis == nil || result.JWTLiveAnalysis.MutationsAccepted != 1 {
		t.Fatalf("accepted mutation was not structured: %+v", result.JWTLiveAnalysis)
	}
}

func TestClassifyJWTLiveIncompleteScanAsInconclusive(t *testing.T) {
	// Given: a live scan that logged a baseline and mutation but never emitted its completion marker.
	input := dto.ToolResult{
		ReturnCode:  0,
		Execution:   dto.ExecutionMetadata{ArgvRedacted: []string{"[REDACTED]", "-t", "https://example.test/me", "-M", "er"}},
		JWTAnalysis: &dto.JWTAnalysisMetadata{ParseStatus: dto.JWTParsed},
		Stdout: `jwttool_original Prescan: original token Response Code: 200, 15 bytes
LAUNCHING SCAN: Forced Errors
jwttool_mutated Injected None into Header Claim: alg Response Code: 401, 8 bytes
`,
	}

	// When: the partial transcript is classified.
	result := classifyToolResult("jwt_analyze", input)

	// Then: observed requests remain available without claiming the selected mode completed.
	if result.FindingStatus != dto.FindingsInconclusive || result.ClassificationReason != "jwt_live_scan_incomplete" || !result.PartialResults {
		t.Fatalf("unexpected incomplete JWT classification: %+v", result)
	}
	if result.JWTLiveAnalysis == nil || result.JWTLiveAnalysis.Completed || result.HTTPRequests == nil || *result.HTTPRequests != 2 {
		t.Fatalf("partial JWT evidence was not preserved: %+v", result)
	}
}
