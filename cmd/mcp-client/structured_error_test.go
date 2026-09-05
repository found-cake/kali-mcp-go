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
