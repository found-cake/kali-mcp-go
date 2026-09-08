package streaming

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
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

func writeStreamDoneEvent(w Writer, result *executor.Result, streamedStderr, callID string) {
	if result == nil {
		writeStreamDoneFallback(w, callID, "internal error: missing stream result")
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
		Execution:          results.ExecutionMetadataFromResult(result),
		Target:             result.Target,
		SPABaseline:        result.SPABaseline,
		FalsePositiveRisk:  result.FalsePositiveRisk,
		Warnings:           result.Warnings,
		Artifacts:          result.Artifacts,
		Progress:           result.Progress,
		JWTAnalysis:        result.JWTAnalysis,
		SQLMapAnalysis:     result.SQLMapAnalysis,
		NucleiPreview:      result.NucleiPreview,
		Evidence:           result.Evidence,
	}
	if terminalErr := terminalStreamError(result, streamedStderr); terminalErr != "" {
		doneEvent.Error = terminalErr
		doneEvent.Failure = &dto.FailureInfo{
			Code:      result.FailureCode,
			Message:   terminalErr,
			Retryable: result.TimedOut || result.Cancelled,
		}
	} else if result.FailureCode != "" {
		doneEvent.Failure = &dto.FailureInfo{
			Code:      result.FailureCode,
			Message:   result.FailureCode,
			Retryable: result.TimedOut || result.Cancelled,
		}
	}
	payload, err := json.Marshal(doneEvent)
	if err != nil {
		writeStreamDoneFallback(w, callID, "internal error: failed to encode done event")
		return
	}
	_ = writeStreamPayload(w, payload)
}
