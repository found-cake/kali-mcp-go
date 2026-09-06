package main

import (
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func classifyToolResult(toolName string, result dto.ToolResult) dto.ToolResult {
	result.FindingTypes = findingTypesForTool(toolName)
	attachReportedRequestCount(toolName, &result)
	if toolName == "dirb_scan" {
		result.DiscoveredPaths = parseDirbDiscoveries(result.Stdout)
	}
	output := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	niktoInternalTimeout := toolName == "nikto_scan" && result.ReturnCode == 0 && !result.TimedOut && !result.Cancelled &&
		strings.Contains(output, "host maximum execution time of") && strings.Contains(output, " seconds reached")
	wpscanNonWordPress := toolName == "wpscan_analyze" && result.ReturnCode == 4 && strings.Contains(
		output, "does not seem to be running wordpress",
	)
	ffufMissingKeyword := toolName == "ffuf_scan" && strings.Contains(
		output, "keyword fuzz defined, but not found in headers, method, url or post data",
	)
	jwtLiveTransportFailed := toolName == "jwt_analyze" && jwtLiveTransportFailure(result)
	semanticFailure := semanticToolFailure(toolName, result, output)
	switch {
	case niktoInternalTimeout:
		result.ExecutionStatus = dto.ExecutionTimedOut
		result.PartialResults = true
		result.ClassificationReason = "nikto_internal_max_time"
	case result.TimedOut:
		result.ExecutionStatus = dto.ExecutionTimedOut
		result.ClassificationReason = "execution_timed_out"
	case result.Cancelled:
		result.ExecutionStatus = dto.ExecutionCancelled
		result.ClassificationReason = "execution_cancelled"
	case ffufMissingKeyword:
		result.ExecutionStatus = dto.ExecutionFailed
		result.ClassificationReason = "ffuf_missing_fuzz_keyword"
	case jwtLiveTransportFailed:
		result.ExecutionStatus = dto.ExecutionFailed
		result.ClassificationReason = "jwt_live_transport_failed"
	case toolName == "osv_scan" && result.ReturnCode == 1 && osvFindingStatus(result.Stdout) == dto.FindingsDetected:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.Success = true
		result.ClassificationReason = "osv_findings_exit_code"
	case wpscanNonWordPress:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.Success = true
		result.ClassificationReason = "wpscan_target_not_wordpress"
	case result.Failure != nil:
		result.ExecutionStatus = dto.ExecutionFailed
		result.ClassificationReason = result.Failure.Code
		if result.ClassificationReason == "" {
			result.ClassificationReason = "tool_reported_failure"
		}
	case semanticFailure != nil:
		result.ExecutionStatus = dto.ExecutionFailed
		result.ClassificationReason = semanticFailure.Code
		result.Failure = semanticFailure
	case result.ReturnCode != 0:
		result.ExecutionStatus = dto.ExecutionFailed
		result.ClassificationReason = "tool_nonzero_exit"
	default:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.ClassificationReason = "no_reliable_finding_classifier"
	}
	result.FindingStatus = dto.FindingsUnknown
	if ffufMissingKeyword {
		result.FindingStatus = dto.FindingsInconclusive
		result.Failure = &dto.FailureInfo{
			Code:    "invalid_fuzz_input",
			Message: "FFUF did not find its FUZZ input placeholder",
		}
	}
	if jwtLiveTransportFailed {
		result.FindingStatus = dto.FindingsInconclusive
		result.PartialResults = true
		result.Failure = &dto.FailureInfo{
			Code:      "jwt_live_transport_failed",
			Message:   "jwt_tool could not reach the live verification target",
			Retryable: true,
		}
	}
	applyIncompleteReportedFinding(toolName, &result, output)
	if wpscanNonWordPress {
		result.FindingStatus = dto.FindingsNotDetected
		result.PartialResults = false
		finalizeClassifiedResult(&result)
		return result
	}
	if toolName == "jwt_analyze" && result.JWTAnalysis != nil && result.JWTAnalysis.ParseStatus != dto.JWTParsed {
		result.ClassificationReason = "jwt_" + string(result.JWTAnalysis.FailureStage) + "_failed"
	}
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		finalizeClassifiedResult(&result)
		return result
	}
	if result.Execution.DryRun {
		result.FindingStatus = dto.FindingsUnknown
		result.ClassificationReason = "dry_run_preview"
		finalizeClassifiedResult(&result)
		return result
	}
	classifySuccessfulFinding(toolName, &result, output)
	finalizeClassifiedResult(&result)
	return result
}
