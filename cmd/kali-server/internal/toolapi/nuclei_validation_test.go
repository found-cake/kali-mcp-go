package toolapi

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestValidateNucleiRequestRejectsUnselectedSafeExecution(t *testing.T) {
	t.Parallel()

	err := validateNucleiRequest(dto.NucleiRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
		Target:      "https://example.test",
	})
	if err == nil || !strings.Contains(err.Error(), "severity, tags, or templates") {
		t.Fatalf("validateNucleiRequest() error = %v, want selector guidance", err)
	}
}

func TestValidateNucleiRequestAllowsBoundedOrExplicitExecution(t *testing.T) {
	t.Parallel()

	requests := []dto.NucleiRequest{
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon}, Target: "https://example.test", DryRun: true},
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon}, Target: "https://example.test", Severity: "high,critical"},
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon}, Target: "https://example.test", Tags: "exposure"},
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon}, Target: "https://example.test", Templates: []string{"http/exposures/"}},
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileExplicitCustom}, Target: "https://example.test"},
	}
	for _, request := range requests {
		if err := validateNucleiRequest(request); err != nil {
			t.Fatalf("validateNucleiRequest(%+v) error = %v, want nil", request, err)
		}
	}
}
