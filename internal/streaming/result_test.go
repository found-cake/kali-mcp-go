package streaming

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestWriteStreamDoneEventPreservesExecutionMetadataAndFailureSemantics(t *testing.T) {
	startedAt := time.Date(2026, time.September, 8, 10, 11, 12, 13, time.UTC)
	execution := dto.ExecutionMetadata{
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
	tests := []struct {
		name           string
		returnCode     int
		stderr         string
		streamedStderr string
		failureCode    string
		wantError      string
		wantFailure    string
	}{
		{
			name: "unstreamed stderr", returnCode: 1, stderr: "already sent\n\nterminal error",
			streamedStderr: "already sent\n", failureCode: "exit_nonzero",
			wantError: "terminal error", wantFailure: "terminal error",
		},
		{name: "failure code only", failureCode: "process_start_failed", wantFailure: "process_start_failed"},
		{name: "success"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: a terminal executor result with fully populated execution metadata.
			result := &executor.Result{
				CallID: "call-terminal", ReturnCode: test.returnCode, Stderr: test.stderr,
				FailureCode: test.failureCode, Tool: "nuclei", ToolVersion: "v3.4.10",
				ArgvRedacted: []string{"nuclei", "-u", "https://example.test"},
				StartedAt:    startedAt, Duration: 1234 * time.Millisecond, Timeout: 17 * time.Second,
				ProcessStarted: true, GracefulStop: 321 * time.Millisecond, DryRun: true,
				Policy: dto.ScanOptions{
					Profile: dto.ProfileSafeRecon, RateLimit: 7, Concurrency: 2,
					HealthURL: "https://example.test/health", Max5xxResponses: 3,
				},
				Controls: execution.Controls,
			}
			buffer := &strings.Builder{}

			// When: the stream terminal event is written.
			writeStreamDoneEvent(bufio.NewWriter(buffer), result, test.streamedStderr, "call-fallback")

			// Then: execution projection and stream-specific failure text remain stable.
			events := parseEvents(t, buffer.String())
			if len(events) != 1 || !events[0].Done || !reflect.DeepEqual(events[0].Execution, execution) {
				t.Fatalf("unexpected terminal event: %+v", events)
			}
			if events[0].Error != test.wantError {
				t.Fatalf("error=%q want=%q", events[0].Error, test.wantError)
			}
			if test.wantFailure == "" {
				if events[0].Failure != nil {
					t.Fatalf("unexpected failure: %+v", events[0].Failure)
				}
				return
			}
			if events[0].Failure == nil || events[0].Failure.Message != test.wantFailure || events[0].Failure.Code != test.failureCode {
				t.Fatalf("unexpected failure: %+v", events[0].Failure)
			}
		})
	}
}
