package dto

import (
	"encoding/json"
	"testing"
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
