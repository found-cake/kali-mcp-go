package dto

import (
	"strconv"
	"strings"
	"testing"
)

func TestToolResultFormatPreservesTextSections(t *testing.T) {
	result := ToolResult{
		Stdout: "out", Stderr: "err",
		Evidence: &EvidenceManifest{GroupID: "group", Artifacts: []EvidenceArtifact{
			{Relation: ArtifactRelationBrowserDOM, Kind: "html", ID: "artifact"},
		}},
	}
	want := "out\n[stderr]\nerr\n\n[evidence group: group]\n- browser_dom (html): artifact"
	if got := result.Format(); got != want {
		t.Fatalf("formatted=%q want=%q", got, want)
	}
}

func BenchmarkToolResultFormat(b *testing.B) {
	artifacts := make([]EvidenceArtifact, 16)
	for index := range artifacts {
		artifacts[index] = EvidenceArtifact{Relation: ArtifactRelationToolResult, Kind: "text", ID: "artifact_" + strconv.Itoa(index)}
	}
	for _, test := range []struct {
		name   string
		result ToolResult
	}{
		{name: "empty"},
		{name: "stdout", result: ToolResult{Stdout: strings.Repeat("o", 32*1024)}},
		{name: "both", result: ToolResult{Stdout: strings.Repeat("o", 32*1024), Stderr: strings.Repeat("e", 16*1024)}},
		{name: "both_truncated", result: ToolResult{Stdout: strings.Repeat("o", 32*1024), Stderr: strings.Repeat("e", 16*1024), OutputTruncated: true}},
		{name: "evidence", result: ToolResult{Stdout: "output", Evidence: &EvidenceManifest{GroupID: "group", Artifacts: artifacts}}},
		{name: "structured_summary", result: ToolResult{Stdout: "output", HTTPResponse: &HTTPResponseMetadata{
			StatusCode: 200, FinalURL: "https://example.test/", BodyBytes: 4096,
			Summary: &HTTPBodySummary{BodySHA256: strings.Repeat("a", 64), JSONKeys: []string{"first", "second", "third"}},
		}}},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if len(test.result.Format()) < len(test.result.Stdout)+len(test.result.Stderr) {
					b.Fatal("formatted output lost content")
				}
			}
		})
	}
}
