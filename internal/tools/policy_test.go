package tools

import (
	"reflect"
	"slices"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestApplyScanControlsAddsNucleiRateAndConcurrencyLimits(t *testing.T) {
	// Given: a Nuclei command and explicit bounded controls.
	args := []string{"nuclei", "-u", "https://example.com"}
	controls := dto.ScanOptions{RateLimit: 5, Concurrency: 2}

	// When: the scan policy is applied.
	got, err := ApplyScanControls(args, controls)
	if err != nil {
		t.Fatalf("apply controls: %v", err)
	}

	// Then: native Nuclei limits are appended.
	want := []string{"nuclei", "-u", "https://example.com", "-rl", "5", "-c", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, got)
	}
}

func TestApplyScanControlsUsesInstalledDalfoxWorkersFlag(t *testing.T) {
	// Given: a Dalfox command and an explicit concurrency limit.
	args := []string{"dalfox", "scan", "https://example.com/?q=FUZZ"}
	controls := dto.ScanOptions{Concurrency: 2}

	// When: the scan policy is applied.
	got, err := ApplyScanControls(args, controls)
	if err != nil {
		t.Fatalf("apply controls: %v", err)
	}

	// Then: the installed Dalfox version's plural workers flag is used.
	want := []string{"dalfox", "scan", "https://example.com/?q=FUZZ", "--workers", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, got)
	}
}

func TestValidateScanProfileRejectsToolOutsideProfile(t *testing.T) {
	// Given: SQLmap is requested under the reconnaissance-only profile.
	controls := dto.ScanOptions{Profile: dto.ProfileSafeRecon}

	// When: the profile is validated for SQLmap.
	err := ValidateScanProfile("sqlmap", controls)

	// Then: the profile rejects the incompatible tool.
	if err == nil {
		t.Fatal("expected safe-recon to reject sqlmap")
	}
}

func TestScanCapabilitiesExposeMCPToolProfileCompatibility(t *testing.T) {
	// Given: the server's canonical scan policy definitions.
	// When: an orchestrator requests scan capabilities.
	capabilities := ScanCapabilities()

	// Then: MCP-facing tool names expose compatible profiles before execution.
	nmap := findToolCapability(t, capabilities.Tools, "nmap_scan")
	if !slices.Contains(nmap.Profiles, dto.ProfileSafeRecon) {
		t.Fatalf("nmap_scan missing safe-recon compatibility: %+v", nmap)
	}
	browser := findToolCapability(t, capabilities.Tools, "browser_check")
	if !slices.Equal(browser.Profiles, []dto.SafetyProfile{dto.ProfileBrowserXSSConfirm, dto.ProfileExplicitCustom}) {
		t.Fatalf("unexpected browser_check profiles: %+v", browser.Profiles)
	}
}

func TestScanControlApplicationSeparatesRequestedAndAppliedValues(t *testing.T) {
	// Given: explicit controls and policy-effective defaults for a tool that supports neither.
	requested := dto.ScanOptions{RateLimit: 4, Concurrency: 3}
	effective := dto.ScanOptions{RateLimit: 10, Concurrency: 2}

	// When: the runtime control application is described for WhatWeb.
	application := ScanControlApplication("whatweb", requested, effective)

	// Then: requested values remain visible without claiming unsupported controls were applied.
	if application.RequestedRateLimit != 4 || application.RequestedConcurrency != 3 || application.AppliedRateLimit != 0 || application.AppliedConcurrency != 0 {
		t.Fatalf("unexpected control application: %+v", application)
	}
}

func findToolCapability(t *testing.T, capabilities []dto.ScanToolCapability, name string) dto.ScanToolCapability {
	t.Helper()
	for _, capability := range capabilities {
		if capability.Tool == name {
			return capability
		}
	}
	t.Fatalf("tool capability not found: %s", name)
	return dto.ScanToolCapability{}
}

func TestNucleiArgsRejectsUnsafeAdditionalArgsByDefault(t *testing.T) {
	// Given: unsafe template tags are smuggled through additional_args.
	request := dto.NucleiRequest{Target: "https://example.com", AdditionalArgs: "-tags dos"}

	// When: Nuclei arguments are generated under the default safe policy.
	_, err := NucleiArgs(request)

	// Then: argument generation rejects the policy bypass.
	if err == nil {
		t.Fatal("expected unsafe Nuclei additional_args to be rejected")
	}
}
