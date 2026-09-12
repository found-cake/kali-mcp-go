package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const jwtConsoleFixture = "\x1b[36mJWT Tool Version 2.3.0\x1b[0m\nheader and payload details"

func TestTextResultSummarizesJWTConsoleNoiseWhenAnalysisIsStructured(t *testing.T) {
	// Given: a successful JWT analysis with noisy console output and structured evidence.
	input := &dto.ToolResult{
		CallID:     "call-jwt-direct",
		ReturnCode: 0,
		Stdout:     jwtConsoleFixture,
		Execution:  dto.ExecutionMetadata{Tool: "jwt_tool"},
		JWTAnalysis: &dto.JWTAnalysisMetadata{
			ParseStatus:  dto.JWTParsed,
			SegmentCount: 3,
			Algorithm:    "RS256",
			ClaimNames:   []string{"sub"},
		},
		Evidence: &dto.EvidenceManifest{
			GroupID: "evidence-jwt",
			Artifacts: []dto.EvidenceArtifact{{
				ID: "artifact-jwt", Kind: "tool-result-json", Relation: dto.ArtifactRelationToolResult,
			}},
		},
	}

	// When: the direct MCP tool path formats the result.
	callResult, structured, err := textResult("jwt_analyze", input, nil)
	if err != nil {
		t.Fatalf("format JWT result: %v", err)
	}
	textContent, ok := callResult.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type: %T", callResult.Content[0])
	}

	// Then: inline text uses structured JWT evidence while structured stdout stays verbatim.
	if strings.Contains(textContent.Text, "\x1b[") || strings.Contains(textContent.Text, "Version 2.3.0") {
		t.Fatalf("JWT inline text retained console noise: %q", textContent.Text)
	}
	if !strings.Contains(textContent.Text, `"jwt_structure"`) || !strings.Contains(textContent.Text, "artifact-jwt") {
		t.Fatalf("JWT inline text omitted structured evidence: %q", textContent.Text)
	}
	if structured.Stdout != jwtConsoleFixture {
		t.Fatalf("structured stdout changed: %q", structured.Stdout)
	}
}

func TestJobResultSummarizesJWTConsoleNoiseWhenAnalysisIsStructured(t *testing.T) {
	// Given: a completed asynchronous JWT job containing the same raw console output.
	rawResult, err := json.Marshal(dto.ToolResult{
		CallID:          "call-jwt-async",
		ReturnCode:      0,
		Stdout:          jwtConsoleFixture,
		ExecutionStatus: dto.ExecutionSucceeded,
		Execution:       dto.ExecutionMetadata{Tool: "jwt_tool"},
		JWTAnalysis: &dto.JWTAnalysisMetadata{
			ParseStatus: dto.JWTParsed, SegmentCount: 3, Algorithm: "RS256",
		},
	})
	if err != nil {
		t.Fatalf("encode JWT fixture: %v", err)
	}

	// When: the asynchronous terminal-result path formats the job.
	callResult, normalized, err := jobMCPResult(&dto.JobResponse{
		JobID: "job-jwt", Status: dto.JobCompleted, Data: rawResult,
	}, nil)
	if err != nil {
		t.Fatalf("format async JWT result: %v", err)
	}
	textContent, ok := callResult.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type: %T", callResult.Content[0])
	}
	var structured dto.ToolResult
	if err := json.Unmarshal(normalized.Data, &structured); err != nil {
		t.Fatalf("decode normalized JWT result: %v", err)
	}

	// Then: async inline text is clean and the normalized job data retains raw stdout.
	if strings.Contains(textContent.Text, "\x1b[") || strings.Contains(textContent.Text, "Version 2.3.0") {
		t.Fatalf("async JWT inline text retained console noise: %q", textContent.Text)
	}
	if !strings.Contains(textContent.Text, `"jwt_structure"`) {
		t.Fatalf("async JWT inline text omitted structured analysis: %q", textContent.Text)
	}
	if structured.Stdout != jwtConsoleFixture {
		t.Fatalf("normalized stdout changed: %q", structured.Stdout)
	}
}
