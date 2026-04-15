package main

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestImplementationVersionDefaultsToDev(t *testing.T) {
	original := version
	version = ""
	t.Cleanup(func() { version = original })

	if got := implementationVersion(); got != "dev" {
		t.Fatalf("expected default version dev, got %q", got)
	}
}

func TestImplementationVersionUsesInjectedValue(t *testing.T) {
	original := version
	version = "1.2.3"
	t.Cleanup(func() { version = original })

	if got := implementationVersion(); got != "1.2.3" {
		t.Fatalf("expected injected version 1.2.3, got %q", got)
	}
}

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
