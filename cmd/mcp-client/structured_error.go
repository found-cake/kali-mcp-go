package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func structuredErrorResult(err error) (*mcp.CallToolResult, dto.ToolResult, error) {
	result := dto.ToolResult{
		Stderr: err.Error(), ReturnCode: -1, ExecutionStatus: dto.ExecutionFailed,
		FindingStatus: dto.FindingsUnknown, ClassificationReason: "transport_failed",
		Failure: &dto.FailureInfo{Code: "transport_error", Message: err.Error()},
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
	result.Finalize()
	result = result.Compact(defaultInlineOutputBytes)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result.Format()}}, IsError: true,
	}, result, nil
}
