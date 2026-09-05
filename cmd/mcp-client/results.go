package main

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func classifyToolResult(toolName string, result dto.ToolResult) dto.ToolResult {
	result.FindingTypes = findingTypesForTool(toolName)
	attachReportedRequestCount(toolName, &result)
	output := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	niktoInternalTimeout := toolName == "nikto_scan" && result.ReturnCode == 0 && !result.TimedOut && !result.Cancelled &&
		strings.Contains(output, "host maximum execution time of") && strings.Contains(output, " seconds reached")
	wpscanNonWordPress := toolName == "wpscan_analyze" && result.ReturnCode == 4 && strings.Contains(
		output, "does not seem to be running wordpress",
	)
	ffufMissingKeyword := toolName == "ffuf_scan" && strings.Contains(
		output, "keyword fuzz defined, but not found in headers, method, url or post data",
	)
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
	case toolName == "osv_scan" && result.ReturnCode == 1 && osvFindingStatus(result.Stdout) == dto.FindingsDetected:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.Success = true
		result.ClassificationReason = "osv_findings_exit_code"
	case wpscanNonWordPress:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.Success = true
		result.ClassificationReason = "wpscan_target_not_wordpress"
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
	switch toolName {
	case "sqlmap_scan":
		switch {
		case strings.Contains(output, "is vulnerable"), strings.Contains(output, "identified the following injection point"):
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "sqlmap_injection_point_reported"
		case strings.Contains(output, "do not appear to be injectable"), strings.Contains(output, "does not seem to be injectable"):
			if result.SQLMapAnalysis != nil && result.SQLMapAnalysis.ManualVerificationRecommended {
				result.FindingStatus = dto.FindingsInconclusive
				result.ClassificationReason = "sqlmap_manual_verification_recommended"
			} else {
				result.FindingStatus = dto.FindingsNotDetected
				result.ClassificationReason = "sqlmap_no_injection_reported"
			}
		}
	case "nmap_scan":
		if strings.Contains(output, "/tcp open") || strings.Contains(output, "/udp open") {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "nmap_open_port_reported"
		} else if strings.Contains(output, "nmap done:") {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "nmap_completed_without_open_port"
		}
	case "nikto_scan":
		if strings.Contains(output, "0 item(s) reported") || strings.Contains(output, "0 items reported") {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "nikto_zero_items_reported"
		} else if strings.Contains(output, "item(s) reported") || strings.Contains(output, " item reported") || strings.Contains(output, " items reported") {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "nikto_items_reported"
		}
	case "gobuster_scan":
		if gobusterReportedFinding(result.Stdout) {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "gobuster_result_reported"
		} else {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "gobuster_completed_without_result"
		}
	case "nuclei_scan", "ffuf_scan", "feroxbuster_scan":
		if strings.TrimSpace(result.Stdout) == "" {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "scanner_completed_without_output"
		} else {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "scanner_emitted_findings"
		}
	case "whatweb_scan":
		if strings.TrimSpace(output) == "" || strings.Contains(output, "error opening:") {
			result.ExecutionStatus = dto.ExecutionFailed
			result.ClassificationReason = "whatweb_reported_open_error"
		} else {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "whatweb_fingerprint_reported"
		}
	case "browser_check":
		var report struct {
			Dialogs []json.RawMessage `json:"dialogs"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err == nil {
			if len(report.Dialogs) > 0 {
				result.FindingStatus = dto.FindingsDetected
				result.ClassificationReason = "browser_dialog_observed"
			} else {
				result.FindingStatus = dto.FindingsNotDetected
				result.ClassificationReason = "browser_completed_without_dialog"
			}
		} else {
			result.ExecutionStatus = dto.ExecutionFailed
			result.ClassificationReason = "browser_report_invalid_json"
			result.Failure = &dto.FailureInfo{Code: "output_parse_failed", Message: "browser output is not valid JSON"}
		}
	case "dalfox_scan":
		var report struct {
			Findings []json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err == nil {
			if len(report.Findings) > 0 {
				result.FindingStatus = dto.FindingsDetected
				result.ClassificationReason = "dalfox_findings_reported"
			} else {
				result.FindingStatus = dto.FindingsNotDetected
				result.ClassificationReason = "dalfox_zero_findings_reported"
			}
		}
	case "retirejs_scan":
		var report struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err == nil && len(report.Data) == 0 {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "retire_zero_findings_reported"
		} else if strings.TrimSpace(result.Stdout) != "" {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "retire_findings_reported"
		}
	case "osv_scan":
		if status := osvFindingStatus(result.Stdout); status != dto.FindingsUnknown {
			result.FindingStatus = status
			result.ClassificationReason = "osv_structured_results"
		} else if strings.Contains(output, "no vulnerabilities found") || strings.Contains(output, "no issues found") {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "osv_no_vulnerabilities_reported"
		}
	case "john_crack":
		if strings.Contains(output, "1g ") || strings.Contains(output, "password hash cracked") {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "john_password_recovered"
		}
	case "jwt_analyze":
		if result.JWTAnalysis != nil && result.JWTAnalysis.ParseStatus == dto.JWTParsed {
			if strings.Contains(output, "cannot find a valid jwt") {
				result.FindingStatus = dto.FindingsInconclusive
				result.PartialResults = true
				result.ClassificationReason = "jwt_live_token_not_observed"
			} else {
				result.ClassificationReason = "jwt_structure_parsed_without_reliable_finding_classifier"
			}
		}
	}
	finalizeClassifiedResult(&result)
	return result
}
