package results

import (
	"reflect"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestExecutionMetadataFromResultMapsEveryField(t *testing.T) {
	// Given: an executor result with every execution metadata source populated.
	startedAt := time.Date(2026, time.September, 8, 10, 11, 12, 13, time.UTC)
	result := &executor.Result{
		Tool:           "nuclei",
		ToolVersion:    "v3.4.10",
		ArgvRedacted:   []string{"nuclei", "-u", "https://example.test"},
		StartedAt:      startedAt,
		Duration:       1234 * time.Millisecond,
		Timeout:        17 * time.Second,
		ProcessStarted: true,
		GracefulStop:   321 * time.Millisecond,
		DryRun:         true,
		Policy: dto.ScanOptions{
			Profile: dto.ProfileSafeRecon, RateLimit: 7, Concurrency: 2,
			HealthURL: "https://example.test/health", Max5xxResponses: 3,
		},
		Controls: dto.ScanControlApplication{
			RequestedRateLimit: 9, AppliedRateLimit: 7,
			RequestedConcurrency: 4, AppliedConcurrency: 2,
		},
	}
	want := dto.ExecutionMetadata{
		Tool:            "nuclei",
		ToolVersion:     "v3.4.10",
		ArgvRedacted:    []string{"nuclei", "-u", "https://example.test"},
		StartedAt:       startedAt,
		EndedAt:         startedAt.Add(1234 * time.Millisecond),
		TimeoutMS:       17000,
		ProcessStarted:  true,
		GracefulStopMS:  321,
		DryRun:          true,
		Profile:         dto.ProfileSafeRecon,
		RateLimit:       7,
		Concurrency:     2,
		HealthURL:       "https://example.test/health",
		Max5xxResponses: 3,
		Controls: dto.ScanControlApplication{
			RequestedRateLimit: 9, AppliedRateLimit: 7,
			RequestedConcurrency: 4, AppliedConcurrency: 2,
		},
	}

	// When: the canonical projection is built.
	got := ExecutionMetadataFromResult(result)

	// Then: every public execution field is mapped without inference.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("execution metadata=%+v want=%+v", got, want)
	}
}
