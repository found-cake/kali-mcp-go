package streaming

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func terminalStreamError(result *executor.Result, streamedStderr string) string {
	if result == nil || result.ReturnCode == 0 || result.Stderr == "" {
		return ""
	}

	terminalErr := result.Stderr
	if streamedStderr != "" && strings.HasPrefix(terminalErr, streamedStderr) {
		terminalErr = strings.TrimPrefix(terminalErr, streamedStderr)
	}

	return strings.TrimLeft(terminalErr, "\n")
}

func writeStreamDoneEvent(w Writer, result *executor.Result, streamedStderr string) {
	if result == nil {
		writeStreamDoneFallback(w, "internal error: missing stream result")
		return
	}
	returnCode := result.ReturnCode
	doneEvent := dto.StreamEvent{
		CallID:             result.CallID,
		Done:               true,
		ReturnCode:         &returnCode,
		TimedOut:           result.TimedOut,
		Cancelled:          result.Cancelled,
		HTTPRequests:       result.HTTPRequests,
		RequestCountSource: result.RequestCountSource,
		DurationMS:         result.Duration.Milliseconds(),
		Execution: dto.ExecutionMetadata{
			Tool:            result.Tool,
			ToolVersion:     result.ToolVersion,
			ArgvRedacted:    result.ArgvRedacted,
			StartedAt:       result.StartedAt,
			EndedAt:         result.StartedAt.Add(result.Duration),
			TimeoutMS:       result.Timeout.Milliseconds(),
			TimeoutPlanning: result.TimeoutPlanning,
			ProcessStarted:  result.ProcessStarted,
			GracefulStopMS:  result.GracefulStop.Milliseconds(),
			DryRun:          result.DryRun,
			Profile:         result.Policy.Profile,
			MaxRequests:     result.Policy.MaxRequests,
			RateLimit:       result.Policy.RateLimit,
			Concurrency:     result.Policy.Concurrency,
			HealthURL:       result.Policy.HealthURL,
			Max5xxResponses: result.Policy.Max5xxResponses,
			Controls:        result.Controls,
		},
		Target:            result.Target,
		SPABaseline:       result.SPABaseline,
		FalsePositiveRisk: result.FalsePositiveRisk,
		Warnings:          result.Warnings,
		Artifacts:         result.Artifacts,
		Progress:          result.Progress,
		JWTAnalysis:       result.JWTAnalysis,
		SQLMapAnalysis:    result.SQLMapAnalysis,
		NucleiPreview:     result.NucleiPreview,
		Evidence:          result.Evidence,
	}
	if terminalErr := terminalStreamError(result, streamedStderr); terminalErr != "" {
		doneEvent.Error = terminalErr
		doneEvent.Failure = &dto.FailureInfo{
			Code:          result.FailureCode,
			Message:       terminalErr,
			Retryable:     result.TimedOut || result.Cancelled,
			RetryEstimate: &dto.RetryEstimate{MaximumRequests: result.Policy.MaxRequests, TimeoutMS: result.Timeout.Milliseconds()},
		}
	} else if result.FailureCode != "" {
		doneEvent.Failure = &dto.FailureInfo{
			Code:          result.FailureCode,
			Message:       result.FailureCode,
			Retryable:     result.TimedOut || result.Cancelled,
			RetryEstimate: &dto.RetryEstimate{MaximumRequests: result.Policy.MaxRequests, TimeoutMS: result.Timeout.Milliseconds()},
		}
	}
	payload, err := json.Marshal(doneEvent)
	if err != nil {
		writeStreamDoneFallback(w, "internal error: failed to encode done event")
		return
	}
	_ = writeStreamPayload(w, payload)
}
