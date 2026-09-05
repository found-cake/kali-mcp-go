package results

import (
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func ToToolResult(result *executor.Result) dto.ToolResult {
	toolResult := dto.ToolResult{
		CallID:             result.CallID,
		Stdout:             result.Stdout,
		Stderr:             result.Stderr,
		StdoutBytes:        len(result.Stdout),
		StderrBytes:        len(result.Stderr),
		ReturnCode:         result.ReturnCode,
		TimedOut:           result.TimedOut,
		Cancelled:          result.Cancelled,
		PartialResults:     result.TimedOut && (result.Stdout != "" || result.Stderr != ""),
		ExecutionStatus:    dto.ExecutionStatusFromResult(result.ReturnCode, result.TimedOut, result.Cancelled),
		FindingStatus:      dto.FindingsUnknown,
		HTTPRequests:       result.HTTPRequests,
		RequestCountSource: result.RequestCountSource,
		DurationMS:         result.Duration.Milliseconds(),
		Execution: dto.ExecutionMetadata{
			Tool:                 result.Tool,
			ToolVersion:          result.ToolVersion,
			ArgvRedacted:         result.ArgvRedacted,
			StartedAt:            result.StartedAt,
			EndedAt:              result.StartedAt.Add(result.Duration),
			TimeoutMS:            result.Timeout.Milliseconds(),
			TimeoutPlanning:      result.TimeoutPlanning,
			ProcessStarted:       result.ProcessStarted,
			GracefulStopMS:       result.GracefulStop.Milliseconds(),
			DryRun:               result.DryRun,
			Profile:              result.Policy.Profile,
			TimeoutRequestBudget: result.Policy.TimeoutRequestBudget,
			RateLimit:            result.Policy.RateLimit,
			Concurrency:          result.Policy.Concurrency,
			HealthURL:            result.Policy.HealthURL,
			Max5xxResponses:      result.Policy.Max5xxResponses,
			Controls:             result.Controls,
		},
		Target:            result.Target,
		SPABaseline:       result.SPABaseline,
		FalsePositiveRisk: result.FalsePositiveRisk,
		Warnings:          result.Warnings,
		Artifacts:         result.Artifacts,
		HTTPRequest:       result.HTTPRequest,
		HTTPResponse:      result.HTTPResponse,
		Progress:          result.Progress,
		JWTAnalysis:       result.JWTAnalysis,
		SQLMapAnalysis:    result.SQLMapAnalysis,
		NucleiPreview:     result.NucleiPreview,
		Evidence:          result.Evidence,
	}
	if toolResult.ExecutionStatus != dto.ExecutionSucceeded {
		toolResult.Failure = &dto.FailureInfo{
			Code:          result.FailureCode,
			Message:       strings.TrimSpace(result.Stderr),
			Retryable:     result.TimedOut || result.Cancelled,
			RetryEstimate: &dto.RetryEstimate{RequestBudget: result.Policy.TimeoutRequestBudget, TimeoutMS: result.Timeout.Milliseconds()},
		}
	}
	toolResult.Finalize()
	return toolResult
}
