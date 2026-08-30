package dto

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestGobusterRequestCarriesTimeout(t *testing.T) {
	t.Parallel()

	request := GobusterRequest{URL: "https://example.com", Timeout: 90}
	if got := request.GetRequestTimeout(); got != 90 {
		t.Fatalf("expected timeout 90, got %d", got)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if string(encoded) != `{"url":"https://example.com","timeout":90}` {
		t.Fatalf("unexpected JSON contract: %s", encoded)
	}
}

func TestToolResultFormatDoesNotClaimPartialOutputWhenTimeoutIsEmpty(t *testing.T) {
	// Given: a timed-out result with no captured process output.
	result := ToolResult{TimedOut: true, PartialResults: false}

	// When: the result is rendered for a human MCP response.
	formatted := result.Format()

	// Then: the summary reports no output instead of claiming partial results.
	if strings.Contains(formatted, "partial results above") {
		t.Fatalf("misleading timeout summary: %q", formatted)
	}
	if !strings.Contains(formatted, "timed out with no output") {
		t.Fatalf("missing empty-timeout summary: %q", formatted)
	}
}

func TestToolResultCarriesMachineReadableStatus(t *testing.T) {
	t.Parallel()

	requestCount := 17
	result := ToolResult{
		ExecutionStatus: ExecutionSucceeded,
		FindingStatus:   FindingsDetected,
		HTTPRequests:    &requestCount,
		Warnings:        []string{"target translated"},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if decoded["execution_status"] != string(ExecutionSucceeded) || decoded["finding_status"] != string(FindingsDetected) {
		t.Fatalf("missing structured status: %s", encoded)
	}
	if decoded["http_requests"] != float64(17) {
		t.Fatalf("missing request count: %s", encoded)
	}
}

func TestToolResultJSONAlwaysCarriesStableExecutionFields(t *testing.T) {
	t.Parallel()

	// Given: a result from a tool whose HTTP request count is not observable.
	result := ToolResult{
		ExecutionStatus: ExecutionSucceeded,
		FindingStatus:   FindingsUnknown,
		DurationMS:      42,
	}

	// When: the result crosses the JSON boundary.
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	// Then: stable fields are present and an unknown request count is null.
	for _, field := range []string{"success", "timed_out", "partial_results", "duration_ms", "http_requests"} {
		if _, ok := decoded[field]; !ok {
			t.Fatalf("missing stable field %q in %s", field, encoded)
		}
	}
	if decoded["http_requests"] != nil {
		t.Fatalf("expected unknown request count to be null: %s", encoded)
	}
}

func TestToolResultCompactLimitsInlineOutputAndReportsOriginalSize(t *testing.T) {
	// Given: a result whose output is too large for an MCP transcript.
	result := ToolResult{Stdout: strings.Repeat("가", 200), Stderr: strings.Repeat("error", 100)}

	// When: the result is compacted for inline delivery.
	compacted := result.Compact(128)

	// Then: previews remain valid UTF-8 and the original sizes stay machine-readable.
	if len(compacted.Stdout) > 160 || len(compacted.Stderr) > 160 || !compacted.OutputTruncated {
		t.Fatalf("output was not compacted: %+v", compacted)
	}
	if compacted.StdoutBytes != len(result.Stdout) || compacted.StderrBytes != len(result.Stderr) {
		t.Fatalf("unexpected original sizes: %+v", compacted)
	}
	if !utf8.ValidString(compacted.Stdout) || !utf8.ValidString(compacted.Stderr) {
		t.Fatal("compacted output is not valid UTF-8")
	}
}

func TestToolResultFinalizeMapsExecutionStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		execution ExecutionStatus
		status    RunStatus
		success   bool
		timedOut  bool
		cancelled bool
		failure   bool
	}{
		{name: "succeeded clears failure", execution: ExecutionSucceeded, status: RunCompleted, success: true},
		{name: "failed keeps failure", execution: ExecutionFailed, status: RunFailed, failure: true},
		{name: "timed out keeps failure", execution: ExecutionTimedOut, status: RunTimeout, timedOut: true, failure: true},
		{name: "cancelled keeps failure", execution: ExecutionCancelled, status: RunCancelled, cancelled: true, failure: true},
		{name: "unknown is failed", execution: ExecutionStatus("future"), status: RunFailed, failure: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: an execution state and an existing failure record.
			result := ToolResult{ExecutionStatus: test.execution, Failure: &FailureInfo{Code: "failure"}}

			// When: the wire result is finalized.
			result.Finalize()

			// Then: the public status flags retain their established mapping.
			if result.Status != test.status || result.Success != test.success || result.TimedOut != test.timedOut || result.Cancelled != test.cancelled {
				t.Fatalf("unexpected finalized result: %+v", result)
			}
			if (result.Failure != nil) != test.failure {
				t.Fatalf("unexpected failure retention: %+v", result.Failure)
			}
		})
	}
}

func TestToolResultFinalizeMarksObservedFailedWorkAsPartial(t *testing.T) {
	// Given: a failed tool result that emitted output and counted parsed requests.
	requestCount := 7
	result := ToolResult{
		ExecutionStatus:    ExecutionFailed,
		Stdout:             "partial scan output",
		HTTPRequests:       &requestCount,
		RequestCountSource: RequestCountParsed,
	}

	// When: the result is normalized for the MCP boundary.
	result.Finalize()

	// Then: partial work and the origin of the request count remain explicit.
	if !result.PartialResults || result.RequestCountSource != RequestCountParsed {
		t.Fatalf("unexpected partial result metadata: %+v", result)
	}
}

func TestToolResultFinalizeMarksUnavailableRequestCountsUnknown(t *testing.T) {
	// Given: a successful tool whose request count cannot be observed.
	result := ToolResult{ExecutionStatus: ExecutionSucceeded}

	// When: the result is normalized for the MCP boundary.
	result.Finalize()

	// Then: the source is unknown without inventing a zero request count.
	if result.RequestCountSource != RequestCountUnknown || result.HTTPRequests != nil {
		t.Fatalf("unexpected request count metadata: %+v", result)
	}
}

func TestExecutionStatusFromResultPreservesPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		returnCode int
		timedOut   bool
		cancelled  bool
		want       ExecutionStatus
	}{
		{name: "success", want: ExecutionSucceeded},
		{name: "nonzero is failed", returnCode: 1, want: ExecutionFailed},
		{name: "cancelled beats nonzero", returnCode: 1, cancelled: true, want: ExecutionCancelled},
		{name: "timeout beats nonzero", returnCode: 1, timedOut: true, want: ExecutionTimedOut},
		{name: "timeout beats cancellation", returnCode: 1, timedOut: true, cancelled: true, want: ExecutionTimedOut},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: primitive process outcome fields from either HTTP transport boundary.
			// When: the shared DTO rule derives the execution status.
			got := ExecutionStatusFromResult(test.returnCode, test.timedOut, test.cancelled)

			// Then: precedence matches the established server and SSE client behavior.
			if got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}
