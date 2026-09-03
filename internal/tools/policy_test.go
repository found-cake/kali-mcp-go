package tools

import (
	"reflect"
	"slices"
	"strings"
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

func TestDalfoxArgsRejectsWorkerFlagsInAdditionalArgs(t *testing.T) {
	// Given: caller-supplied flags that bypass the versioned concurrency control.
	additionalArgs := []string{"--worker 2", "--workers 2", "--worker=2", "--workers=2"}

	for _, extra := range additionalArgs {
		t.Run(extra, func(t *testing.T) {
			// When: Dalfox arguments are generated from the request.
			_, err := DalfoxArgs(dto.DalfoxRequest{
				Target: "https://example.com/?q=FUZZ", AdditionalArgs: extra,
			})

			// Then: callers are directed to the MCP concurrency field instead.
			if err == nil || !strings.Contains(err.Error(), "concurrency") {
				t.Fatalf("expected worker flag rejection, got %v", err)
			}
		})
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

func TestEffectiveScanOptionsRejectsUnsupportedExplicitControl(t *testing.T) {
	_, err := EffectiveScanOptions("whatweb", dto.ScanOptions{RateLimit: 4})
	if err == nil || !strings.Contains(err.Error(), "rate_limit is not supported") {
		t.Fatalf("expected unsupported rate limit rejection, got %v", err)
	}
}

func TestEffectiveScanOptionsAppliesOnlyEnforceableProfileDefaults(t *testing.T) {
	whatweb, err := EffectiveScanOptions("whatweb", dto.ScanOptions{Profile: dto.ProfileSafeRecon})
	if err != nil {
		t.Fatalf("apply WhatWeb profile: %v", err)
	}
	if whatweb.RateLimit != 0 || whatweb.Concurrency != 0 || whatweb.MaxRequests != 0 || whatweb.Max5xxResponses != 0 {
		t.Fatalf("unsupported defaults were presented as effective: %+v", whatweb)
	}

	nmap, err := EffectiveScanOptions("nmap", dto.ScanOptions{Profile: dto.ProfileSafeRecon})
	if err != nil {
		t.Fatalf("apply Nmap profile: %v", err)
	}
	if nmap.RateLimit != 10 || nmap.MaxRequests != 2000 || nmap.Concurrency != 0 || nmap.Max5xxResponses != 0 {
		t.Fatalf("Nmap profile did not preserve only enforceable defaults: %+v", nmap)
	}
}

func TestScanControlApplicationReportsEnforcementMethod(t *testing.T) {
	requested := dto.ScanOptions{MaxRequests: 50}
	effective := dto.ScanOptions{RateLimit: 10, Concurrency: 2, MaxRequests: 50, Max5xxResponses: 20}
	application := ScanControlApplication("ffuf", requested, effective)

	methods := make(map[dto.ScanControl]dto.AppliedScanControl)
	for _, control := range application.Controls {
		methods[control.Control] = control
	}
	if methods[dto.ScanControlMaxRequests].Enforcement != dto.ControlDerivedTimeout || !methods[dto.ScanControlMaxRequests].Applied {
		t.Fatalf("max request enforcement is not explicit: %+v", application)
	}
	if methods[dto.ScanControlMax5xx].Enforcement != dto.ControlOutputObserver || !methods[dto.ScanControlMax5xx].Applied {
		t.Fatalf("5xx enforcement is not explicit: %+v", application)
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

func TestNucleiArgsRejectsSafetyOverridesByDefault(t *testing.T) {
	// Given: arguments that select unsafe work or override mandatory safety flags.
	tests := []string{
		"-tags dos",
		"--tags=dos",
		"-itags dos",
		"--include-tags=dos",
		"-t=path/to/dos.yaml",
		"--templates path/to/dos.yaml",
		"-it path/to/excluded.yaml",
		"--include-templates=path/to/excluded.yaml",
		"-fuzz",
		"-dast",
		"-no-interactsh=false",
		"--interactsh-server=https://oast.example",
		"-itoken=secret",
		"-etags=",
		"--exclude-tags safe",
	}

	for _, additionalArgs := range tests {
		t.Run(additionalArgs, func(t *testing.T) {
			// When: Nuclei arguments are generated under the default safe policy.
			_, err := NucleiArgs(dto.NucleiRequest{
				Target:         "https://example.com",
				AdditionalArgs: additionalArgs,
			})

			// Then: the policy override is rejected before Nuclei starts.
			if err == nil {
				t.Fatalf("unsafe additional_args accepted: %q", additionalArgs)
			}
		})
	}
}

func TestNucleiArgsRejectsInlineValueForFlagOnlyOption(t *testing.T) {
	_, err := NucleiArgs(dto.NucleiRequest{
		Target: "https://example.com", AdditionalArgs: "--stats=true",
	})
	if err == nil || !strings.Contains(err.Error(), "does not accept an inline value") {
		t.Fatalf("flag-only option accepted an inline value: %v", err)
	}
}

func TestNucleiArgsAllowSafetyOverridesOnlyWhenExplicit(t *testing.T) {
	// Given: the caller explicitly authorizes unsafe Nuclei behavior.
	request := dto.NucleiRequest{
		Target:         "https://example.com",
		AllowUnsafe:    true,
		AdditionalArgs: "--include-tags=dos -no-interactsh=false",
	}

	// When: Nuclei arguments are generated.
	args, err := NucleiArgs(request)

	// Then: the explicit override remains available and no safe-mode flags are injected.
	if err != nil {
		t.Fatalf("build explicitly unsafe Nuclei args: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--include-tags=dos") || strings.Contains(joined, "-etags dos,fuzz,dast,oast,interactsh") || strings.Contains(joined, "-no-interactsh -") {
		t.Fatalf("unexpected explicitly unsafe Nuclei args: %v", args)
	}
}

func TestNucleiArgsKeepSafeModeFlagsAfterAllowedAdditionalArgs(t *testing.T) {
	// Given: an authenticated safe scan using allowlisted operational flags.
	request := dto.NucleiRequest{
		Target:         "https://example.com",
		AdditionalArgs: "-silent -H 'Authorization: Bearer test-token'",
	}

	// When: Nuclei arguments are generated.
	args, err := NucleiArgs(request)

	// Then: caller arguments are retained while immutable safety flags remain last.
	if err != nil {
		t.Fatalf("build safe Nuclei args: %v", err)
	}
	wantSuffix := []string{"-etags", "dos,fuzz,dast,oast,interactsh", "-no-interactsh"}
	if len(args) < len(wantSuffix) || !slices.Equal(args[len(args)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("safe-mode flags are not final: %v", args)
	}
}

func TestNucleiSafeModeRejectsCrossHostRedirects(t *testing.T) {
	_, err := NucleiArgs(dto.NucleiRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
		Target:      "https://example.test", AdditionalArgs: "-fr",
	})
	if err == nil {
		t.Fatal("safe Nuclei accepted cross-host redirects")
	}
}

func TestNucleiArgsRejectsUnsafeTypedSelectorsByDefault(t *testing.T) {
	// Given: unsafe selectors supplied through the typed fields.
	tests := []dto.NucleiRequest{
		{Target: "https://example.com", Tags: "dast"},
		{Target: "https://example.com", Tags: "fuzzing"},
		{Target: "https://example.com", Templates: []string{"http/dos/resource-exhaustion.yaml"}},
		{Target: "https://example.com", Templates: []string{"http/oast/callback.yaml"}},
	}

	for index, request := range tests {
		// When: typed selectors are converted into Nuclei arguments.
		_, err := NucleiArgs(request)

		// Then: unsafe selection still requires explicit authorization.
		if err == nil {
			t.Fatalf("unsafe typed selector %d was accepted: %+v", index, request)
		}
	}
}
