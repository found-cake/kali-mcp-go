package tools

import (
	"reflect"
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
