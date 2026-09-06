package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func structuredErrorResult(name string, partial *dto.ToolResult, err error) (*mcp.CallToolResult, dto.ToolResult, error) {
	result := dto.ToolResult{}
	if partial != nil {
		result = *partial
	}
	partialEvidence := result.PartialResults || result.Stdout != "" || result.Stderr != "" || result.HTTPRequests != nil || result.Progress != nil && result.Progress.ObservedOutputItems > 0
	result.ReturnCode = -1
	result.ExecutionStatus = dto.ExecutionFailed
	result.FindingStatus = dto.FindingsUnknown
	result.ClassificationReason = "transport_failed"
	result.Failure = &dto.FailureInfo{Code: "transport_error", Message: err.Error()}
	if result.Stderr == "" {
		result.Stderr = err.Error()
	}
	var serverError *kaliclient.ServerError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		result.ExecutionStatus = dto.ExecutionTimedOut
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "client_timeout"
		result.Failure = &dto.FailureInfo{Code: "client_timeout", Message: err.Error(), Retryable: true}
	case errors.Is(err, context.Canceled):
		result.ExecutionStatus = dto.ExecutionCancelled
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "client_cancelled"
		result.Failure = &dto.FailureInfo{Code: "client_cancelled", Message: err.Error(), Retryable: true}
	case errors.As(err, &serverError):
		result.CallID = serverError.CallID
		result.Stderr = serverError.Message()
		result.ClassificationReason = "server_request_failed"
		result.Failure = &dto.FailureInfo{
			Code: "server_error", Message: serverError.Message(), Retryable: serverError.StatusCode >= http.StatusInternalServerError,
		}
		if serverError.StatusCode == http.StatusBadRequest {
			result.FindingStatus = dto.FindingsInconclusive
			result.ClassificationReason = "request_validation_failed"
			result.Failure.Code = "invalid_input"
			result.Failure.Retryable = false
		}
	}
	result.PartialResults = partialEvidence
	if partialEvidence {
		classified := classifyToolResult(name, result)
		result.FindingStatus = classified.FindingStatus
	}
	result.Finalize()
	result = result.Compact(defaultInlineOutputBytes)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result.Format()}}, IsError: true,
	}, result, nil
}
