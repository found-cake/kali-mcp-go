package main

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestCompactToolResultKeepsOnlyCompleteNucleiLines(t *testing.T) {
	// Given: one complete finding followed by a line that exceeds the Nuclei inline budget.
	firstLine := strings.Repeat("a", 1500) + "\n"
	fullOutput := firstLine + strings.Repeat("b", 1500) + "\n"
	result := dto.ToolResult{Stdout: fullOutput}

	// When: the result is prepared for inline MCP delivery.
	compacted := compactToolResult("nuclei_scan", result)

	// Then: callers receive only valid complete lines and can page the full artifact separately.
	if compacted.Stdout != firstLine || !compacted.OutputTruncated || compacted.StdoutBytes != len(fullOutput) {
		t.Fatalf("unexpected Nuclei preview: %+v", compacted)
	}
}

func TestCompactToolResultOmitsOversizedFirstNucleiLine(t *testing.T) {
	// Given: a single Nuclei JSONL record larger than the inline budget.
	fullOutput := strings.Repeat("x", 3000) + "\n"

	// When: the result is prepared for inline MCP delivery.
	compacted := compactToolResult("nuclei_scan", dto.ToolResult{Stdout: fullOutput})

	// Then: a broken partial JSON record is not returned as if it could be parsed.
	if compacted.Stdout != "" || !compacted.OutputTruncated || compacted.StdoutBytes != len(fullOutput) {
		t.Fatalf("oversized Nuclei line was partially exposed: %+v", compacted)
	}
}

func TestCompactToolResultSeparatesFindingAndArtifactCompleteness(t *testing.T) {
	// Given: oversized Nuclei finding and diagnostic channels with a retained full result artifact.
	fullLine := strings.Repeat("x", 3000) + "\n"
	result := dto.ToolResult{
		Stdout: fullLine,
		Stderr: fullLine,
		Artifacts: []dto.ArtifactRef{{
			ID: "artifact_full", Relation: dto.ArtifactRelationToolResult,
		}},
	}

	// When: the result is bounded for inline MCP delivery.
	compacted := compactToolResult("nuclei_scan", result)

	// Then: channel truncation, finding truncation, and artifact completeness remain distinct.
	if !compacted.OutputTruncated || !compacted.StdoutTruncated || !compacted.StderrTruncated {
		t.Fatalf("missing channel truncation metadata: %+v", compacted)
	}
	if !compacted.FindingOutputTruncated || !compacted.ArtifactComplete {
		t.Fatalf("missing finding or artifact completeness metadata: %+v", compacted)
	}
}
