package dto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToolResultJSONIncludesFalseSuccess(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(ToolResult{ReturnCode: 1, Success: false, TimedOut: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"success":false`) {
		t.Fatalf("expected success=false field in %s", got)
	}
}

func TestStreamEventJSONIncludesZeroReturnCode(t *testing.T) {
	t.Parallel()

	returnCode := 0
	data, err := json.Marshal(StreamEvent{Done: true, ReturnCode: &returnCode, TimedOut: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"return_code":0`) {
		t.Fatalf("expected return_code=0 field in %s", got)
	}
}

func TestStreamEventJSONOmitsReturnCodeBeforeDone(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(StreamEvent{Stream: "stdout", Line: "hello"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)
	if strings.Contains(got, `"return_code":`) {
		t.Fatalf("expected return_code to be omitted in %s", got)
	}
}
