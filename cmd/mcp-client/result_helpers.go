package main

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func gobusterReportedFinding(output string) bool {
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/") || strings.HasPrefix(strings.ToLower(line), "found:") || strings.Contains(line, "(Status:") || strings.HasPrefix(line, "[Status=") {
			return true
		}
	}
	return false
}

func finalizeClassifiedResult(result *dto.ToolResult) {
	if result.ExecutionStatus != dto.ExecutionSucceeded && result.Failure == nil {
		code := "nonzero_exit"
		retryable := false
		switch result.ExecutionStatus {
		case dto.ExecutionTimedOut:
			code = "timed_out"
			retryable = true
		case dto.ExecutionCancelled:
			code = "cancelled"
			retryable = true
		case dto.ExecutionFailed:
		default:
		}
		message := strings.TrimSpace(result.Stderr)
		if message == "" {
			message = strings.TrimSpace(result.Stdout)
		}
		result.Failure = &dto.FailureInfo{Code: code, Message: message, Retryable: retryable}
	}
	result.Finalize()
	if result.ExecutionStatus == dto.ExecutionTimedOut || result.ExecutionStatus == dto.ExecutionCancelled || result.ExecutionStatus == dto.ExecutionFailed && result.PartialResults {
		result.FindingStatus = dto.FindingsInconclusive
	}
}

func osvFindingStatus(stdout string) dto.FindingStatus {
	var report struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &report); err != nil {
		return dto.FindingsUnknown
	}
	if len(report.Results) > 0 {
		return dto.FindingsDetected
	}
	return dto.FindingsNotDetected
}
