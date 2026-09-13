package main

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const maximumNucleiFindings = 100

func attachNucleiFindings(result *dto.ToolResult) {
	findings, total, _ := parseNucleiFindings(result.Stdout)
	result.NucleiFindings = findings
	result.NucleiFindingsTotal = total
	result.NucleiFindingsTruncated = total > len(findings)
}

func parseNucleiFindings(output string) ([]dto.NucleiFinding, int, bool) {
	findings := make([]dto.NucleiFinding, 0, min(maximumNucleiFindings, strings.Count(output, "\n")))
	total := 0
	malformed := false
	for line := range strings.Lines(output) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || nucleiDiagnosticLine(trimmed) {
			continue
		}
		var event struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			MatcherName string `json:"matcher-name"`
			Type        string `json:"type"`
			MatchedAt   string `json:"matched-at"`
		}
		if err := json.Unmarshal([]byte(trimmed), &event); err != nil {
			malformed = true
			continue
		}
		if event.TemplateID == "" {
			continue
		}
		total++
		if len(findings) == maximumNucleiFindings {
			continue
		}
		findings = append(findings, dto.NucleiFinding{
			TemplateID: event.TemplateID, Name: event.Info.Name, Severity: event.Info.Severity,
			MatcherName: event.MatcherName, Type: event.Type, MatchedAt: event.MatchedAt,
		})
	}
	return findings, total, malformed
}
