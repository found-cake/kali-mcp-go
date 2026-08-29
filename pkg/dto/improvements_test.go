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

	result := ToolResult{
		ExecutionStatus: ExecutionSucceeded,
		FindingStatus:   FindingsDetected,
		HTTPRequests:    17,
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
