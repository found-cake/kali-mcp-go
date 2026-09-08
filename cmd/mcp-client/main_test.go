package main

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestFormatScanCapabilitiesExplainsExecutionContract(t *testing.T) {
	result := &dto.ScanCapabilitiesResult{Tools: []dto.ScanToolCapability{{
		Tool: "ffuf_scan", TargetInputFormat: dto.TargetInputWebURL,
		Profiles:    []dto.SafetyProfile{dto.ProfileSafeRecon},
		Controls:    []dto.ScanControlCapability{{Control: dto.ScanControlRateLimit, Enforcement: dto.ControlNativeCLI}},
		ImpactLevel: dto.ImpactActive, ExecutionMode: dto.ToolExecutionStream,
		AvailabilityChecked: true, Available: true,
	}}}

	formatted := formatScanCapabilities(result)
	for _, value := range []string{"available=true", "impact=active", "mode=stream", "rate_limit:native_cli"} {
		if !strings.Contains(formatted, value) {
			t.Fatalf("capability summary is missing %q: %s", value, formatted)
		}
	}
}

func TestFormatScanCapabilitiesIncludesProfileLimits(t *testing.T) {
	// Given: a profile with bounded scan controls.
	result := &dto.ScanCapabilitiesResult{Profiles: []dto.ScanProfileCapability{{
		Profile: dto.ProfileWebDiscoveryLowRate,
		Tools:   []string{"ffuf_scan", "feroxbuster_scan"},
		Limits: dto.ScanLimits{
			RateLimit: 5, Concurrency: 2, Max5xxResponses: 10,
		},
	}}}

	// When: capabilities are formatted for the MCP text response.
	formatted := formatScanCapabilities(result)

	// Then: the model sees every effective profile limit before choosing options.
	for _, value := range []string{"rate_limit=5", "concurrency=2", "max_5xx_responses=10"} {
		if !strings.Contains(formatted, value) {
			t.Fatalf("profile limit summary is missing %q: %s", value, formatted)
		}
	}
}

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
