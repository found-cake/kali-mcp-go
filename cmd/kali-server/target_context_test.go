package main

import (
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTargetContextSelectsNetworkFormWithoutServerState(t *testing.T) {
	// Given: an explicitly resolved Docker-host candidate and a signed context.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{
			{
				BrowserTarget: "http://host.docker.internal:3000/",
				NetworkTarget: "host.docker.internal",
				Port:          3000,
				Scope:         dto.TargetScopeDockerHost,
			},
		},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}
	if err := attachTargetContexts("secret", &result, issued); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}

	// When: Nmap supplies only the selected candidate context.
	request := dto.NmapRequest{ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext}}
	normalized, err := applyRequestTargetContext("secret", request, now)
	if err != nil {
		t.Fatalf("apply target context: %v", err)
	}
	provenance, err := resolveTargetProvenance(normalized, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the network form is explicit, verified, and tied to the original target.
	if normalized.Target != "host.docker.internal" {
		t.Fatalf("unexpected network target: %s", normalized.Target)
	}
	if !provenance.Verified || provenance.Original != result.OriginalTarget || provenance.Selected != normalized.Target {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
}

func TestResolutionLifetimeRejectsExcessiveValidity(t *testing.T) {
	// Given: a requested context lifetime above the server maximum.
	// When: the bounded lifetime is parsed.
	_, err := resolutionLifetime(3601)

	// Then: the resolver rejects the oversized validity window.
	if err == nil {
		t.Fatal("expected excessive target context lifetime to be rejected")
	}
}
