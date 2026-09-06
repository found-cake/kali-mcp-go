package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTextResultReturnsStructuredValidationFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set(dto.CallIDHeader, "call_validation")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, `{"error":"FUZZ must appear in url or additional_args"}`)
	}))
	defer server.Close()

	_, requestError := kaliclient.New(server.URL, time.Second, "").Stream(
		context.Background(), "/api/tools/ffuf/stream", dto.FFUFRequest{},
	)
	mcpResult, structured, err := textResult("ffuf_scan", nil, requestError)
	if err != nil {
		t.Fatalf("textResult() error = %v, want a structured MCP failure", err)
	}
	if mcpResult == nil || !mcpResult.IsError {
		t.Fatalf("MCP result = %#v, want isError=true", mcpResult)
	}
	if structured.CallID != "call_validation" || structured.ExecutionStatus != dto.ExecutionFailed || structured.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("unexpected structured validation failure: %+v", structured)
	}
	if structured.Failure == nil || structured.Failure.Code != "invalid_input" {
		t.Fatalf("failure = %#v, want invalid_input", structured.Failure)
	}
	if structured.Failure.Message != "FUZZ must appear in url or additional_args" {
		t.Fatalf("failure message = %q", structured.Failure.Message)
	}
}

func TestTextResultReturnsStructuredServerFailure(t *testing.T) {
	requestError := &kaliclient.ServerError{
		StatusCode: http.StatusServiceUnavailable,
		CallID:     "call_server_failure",
		Body:       `{"error":"scan capacity exceeded"}`,
	}

	mcpResult, structured, err := textResult("nuclei_scan", nil, requestError)
	if err != nil {
		t.Fatalf("textResult() error = %v, want a structured MCP failure", err)
	}
	if mcpResult == nil || !mcpResult.IsError || structured.CallID != "call_server_failure" {
		t.Fatalf("server failure was not structured: result=%#v structured=%+v", mcpResult, structured)
	}
	if structured.Failure == nil || structured.Failure.Code != "server_error" || structured.ExecutionStatus != dto.ExecutionFailed {
		t.Fatalf("unexpected server failure envelope: %+v", structured)
	}
}

func TestTextResultReturnsStructuredDeadlineFailure(t *testing.T) {
	mcpResult, structured, err := textResult("nuclei_scan", nil, context.DeadlineExceeded)
	if err != nil {
		t.Fatalf("textResult() error = %v, want a structured MCP timeout", err)
	}
	if mcpResult == nil || !mcpResult.IsError || structured.ExecutionStatus != dto.ExecutionTimedOut || !structured.TimedOut {
		t.Fatalf("deadline failure was not structured: result=%#v structured=%+v", mcpResult, structured)
	}
	if structured.Failure == nil || structured.Failure.Code != "client_timeout" || !structured.Failure.Retryable {
		t.Fatalf("unexpected timeout failure envelope: %+v", structured)
	}
}

func TestTextResultPreservesPartialOutputOnDeadline(t *testing.T) {
	partial := &dto.ToolResult{CallID: "call_partial", Stdout: "partial finding\n", PartialResults: true}

	_, structured, err := textResult("nuclei_scan", partial, context.DeadlineExceeded)
	if err != nil {
		t.Fatalf("textResult() error = %v, want a structured partial timeout", err)
	}
	if structured.CallID != "call_partial" || structured.Stdout != "partial finding\n" || !structured.PartialResults {
		t.Fatalf("partial timeout evidence was discarded: %+v", structured)
	}
	if structured.ExecutionStatus != dto.ExecutionTimedOut || structured.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("partial timeout status is inconsistent: %+v", structured)
	}
}

func TestTextResultPreservesPartialNucleiMetadataOnDeadline(t *testing.T) {
	// Given: a client deadline after Nuclei emitted scheduled-work statistics and progress.
	partial := &dto.ToolResult{
		CallID:         "call_partial_nuclei",
		Stderr:         "{\"duration\":\"0:00:05\",\"requests\":\"40\",\"startedAt\":\"2026-09-05T12:00:00Z\"}\n",
		PartialResults: true,
		Progress:       &dto.ProgressMetadata{Phase: dto.ProgressCompleted},
	}

	// When: the interrupted stream is converted to an MCP result.
	_, structured, err := textResult("nuclei_scan", partial, context.DeadlineExceeded)
	// Then: runtime semantics survive without claiming measured request delivery.
	if err != nil {
		t.Fatalf("textResult() error = %v", err)
	}
	if structured.NucleiRuntime == nil || structured.NucleiRuntime.RequestsSemantics != dto.NucleiRequestsScheduled {
		t.Fatalf("Nuclei runtime metadata was discarded: %+v", structured)
	}
	if structured.HTTPRequests != nil || structured.Progress.Phase != dto.ProgressTimedOut {
		t.Fatalf("partial timeout metadata is contradictory: %+v", structured)
	}
}
