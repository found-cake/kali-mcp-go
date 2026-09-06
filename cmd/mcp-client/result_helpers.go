package main

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func jwtLiveTransportFailure(result dto.ToolResult) bool {
	if result.JWTAnalysis == nil || result.JWTAnalysis.ParseStatus != dto.JWTParsed || !slices.Contains(result.Execution.ArgvRedacted, "-t") {
		return false
	}
	output := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	for _, signature := range []string{
		"proxyerror",
		"connectionerror",
		"nameresolutionerror",
		"failed to establish a new connection",
		"failed to resolve",
		"name or service not known",
		"temporary failure in name resolution",
		"nodename nor servname provided",
		"max retries exceeded with url:",
	} {
		if strings.Contains(output, signature) {
			return true
		}
	}
	return false
}

func nucleiReportedFinding(output string) bool {
	for line := range strings.Lines(output) {
		var event struct {
			TemplateID string `json:"template-id"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &event); err == nil && event.TemplateID != "" {
			return true
		}
	}
	return false
}

func ffufReportedFinding(output string) bool {
	for line := range strings.Lines(output) {
		var result struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &result); err == nil && result.URL != "" && result.Status >= 100 && result.Status <= 599 {
			return true
		}
	}
	return false
}

func feroxbusterReportedFinding(output string) bool {
	for line := range strings.Lines(output) {
		var result struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &result); err == nil && result.Type == "response" && result.URL != "" && result.Status >= 100 && result.Status <= 599 {
			return true
		}
	}
	return false
}

func niktoReportedFinding(output string) bool {
	for line := range strings.Lines(output) {
		fields := strings.Fields(strings.ToLower(line))
		for index := 1; index+1 < len(fields); index++ {
			if fields[index] != "item" && fields[index] != "items" && fields[index] != "item(s)" {
				continue
			}
			count, err := strconv.Atoi(fields[index-1])
			if err == nil && count > 0 && strings.Trim(fields[index+1], ":.,") == "reported" {
				return true
			}
		}
	}
	return false
}

func applyIncompleteReportedFinding(toolName string, result *dto.ToolResult, combinedOutput string) {
	if result.ExecutionStatus == dto.ExecutionSucceeded {
		return
	}
	found := false
	switch toolName {
	case "nuclei_scan":
		found = nucleiReportedFinding(result.Stdout)
	case "ffuf_scan":
		found = ffufReportedFinding(result.Stdout)
	case "nikto_scan":
		found = niktoReportedFinding(combinedOutput)
	case "feroxbuster_scan":
		found = feroxbusterReportedFinding(result.Stdout)
	}
	if !found {
		return
	}
	result.FindingStatus = dto.FindingsDetected
	result.PartialResults = true
	result.ClassificationReason = strings.TrimSuffix(toolName, "_scan") + "_partial_finding_reported"
}

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
	if result.FindingStatus != dto.FindingsDetected && (result.ExecutionStatus == dto.ExecutionTimedOut || result.ExecutionStatus == dto.ExecutionCancelled || result.ExecutionStatus == dto.ExecutionFailed && result.PartialResults) {
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
