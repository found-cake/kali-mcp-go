package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyNucleiResultStructuresFindingRecords(t *testing.T) {
	// Given: Nuclei JSONL containing matcher-specific findings.
	stdout := nucleiFindingFixture(dto.NucleiFinding{TemplateID: "missing-csp", MatcherName: "content-security-policy", Severity: "medium"}, 0) +
		nucleiFindingFixture(dto.NucleiFinding{TemplateID: "swagger-api", MatcherName: "swagger", Severity: "high"}, 0)

	// When: the common result classifier processes the JSONL.
	result := classifyToolResult("nuclei_scan", dto.ToolResult{ReturnCode: 0, Stdout: stdout})

	// Then: compact finding identities are exposed without embedding raw request or response bodies.
	if result.NucleiFindingsTotal != 2 || result.NucleiFindingsTruncated || len(result.NucleiFindings) != 2 {
		t.Fatalf("unexpected Nuclei finding summary: %+v", result)
	}
	first := result.NucleiFindings[0]
	if first.TemplateID != "missing-csp" || first.Name != "Fixture finding" || first.Severity != "medium" || first.MatcherName != "content-security-policy" || first.Type != "http" || first.MatchedAt != "https://example.test/" {
		t.Fatalf("unexpected first Nuclei finding: %+v", first)
	}
}

func TestCompactNucleiResultBoundsStructuredFindingsIndependentlyFromRawOutput(t *testing.T) {
	// Given: more Nuclei findings than the structured response bound, each carrying a large raw request.
	var stdout strings.Builder
	for index := range maximumNucleiFindings + 1 {
		stdout.WriteString(nucleiFindingFixture(dto.NucleiFinding{TemplateID: fmt.Sprintf("finding-%03d", index), MatcherName: "body", Severity: "low"}, 300))
	}

	// When: the result is classified and its raw inline output is compacted.
	result := compactToolResult("nuclei_scan", classifyToolResult("nuclei_scan", dto.ToolResult{ReturnCode: 0, Stdout: stdout.String()}))

	// Then: the complete artifact can remain authoritative while the typed preview reports its own bound.
	if len(result.NucleiFindings) != maximumNucleiFindings || result.NucleiFindingsTotal != maximumNucleiFindings+1 || !result.NucleiFindingsTruncated {
		t.Fatalf("unexpected bounded findings: count=%d total=%d truncated=%t", len(result.NucleiFindings), result.NucleiFindingsTotal, result.NucleiFindingsTruncated)
	}
	if !result.StdoutTruncated || !result.FindingOutputTruncated {
		t.Fatalf("raw output truncation was not kept distinct: %+v", result)
	}
}

func nucleiFindingFixture(finding dto.NucleiFinding, padding int) string {
	return fmt.Sprintf(`{"template-id":%q,"info":{"name":"Fixture finding","severity":%q},"matcher-name":%q,"type":"http","matched-at":"https://example.test/","request":%q}`+"\n",
		finding.TemplateID, finding.Severity, finding.MatcherName, strings.Repeat("x", padding))
}
