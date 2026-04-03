package main

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestFormatHealthSummaryIncludesEssentialReadiness(t *testing.T) {
	t.Parallel()

	summary := formatHealthSummary(&dto.HealthResult{
		Status:                     "degraded",
		Message:                    "kali-server running with missing essential tools",
		AllEssentialToolsAvailable: false,
		ToolsStatus: map[string]bool{
			"john": false,
			"nmap": true,
		},
	})

	if !strings.Contains(summary, "essential tools ready: no") {
		t.Fatalf("expected essential readiness line, got %q", summary)
	}
	if !strings.Contains(summary, "✗ john (missing)") || !strings.Contains(summary, "✓ nmap") {
		t.Fatalf("expected tool status details, got %q", summary)
	}
}
