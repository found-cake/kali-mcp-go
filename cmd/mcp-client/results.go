package main

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func classifyToolResult(toolName string, result dto.ToolResult) dto.ToolResult {
	switch {
	case result.TimedOut:
		result.ExecutionStatus = dto.ExecutionTimedOut
		result.ClassificationReason = "execution_timed_out"
	case toolName == "osv_scan" && result.ReturnCode == 1 && osvFindingStatus(result.Stdout) == dto.FindingsDetected:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.Success = true
		result.ClassificationReason = "osv_findings_exit_code"
	case result.ReturnCode != 0:
		result.ExecutionStatus = dto.ExecutionFailed
		result.ClassificationReason = "tool_nonzero_exit"
	default:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.ClassificationReason = "no_reliable_finding_classifier"
	}
	result.FindingStatus = dto.FindingsUnknown
	if toolName == "jwt_analyze" && result.JWTAnalysis != nil && result.JWTAnalysis.ParseStatus != dto.JWTParsed {
		result.ClassificationReason = "jwt_" + string(result.JWTAnalysis.FailureStage) + "_failed"
	}
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		finalizeClassifiedResult(&result)
		return result
	}
	output := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	switch toolName {
	case "sqlmap_scan":
		switch {
		case strings.Contains(output, "is vulnerable"), strings.Contains(output, "identified the following injection point"):
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "sqlmap_injection_point_reported"
		case strings.Contains(output, "do not appear to be injectable"), strings.Contains(output, "does not seem to be injectable"):
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "sqlmap_no_injection_reported"
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
		} else if strings.Contains(output, "item(s) reported") || strings.Contains(output, "items reported") {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "nikto_items_reported"
		}
	case "nuclei_scan", "ffuf_scan", "gobuster_scan", "feroxbuster_scan":
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
			result.ClassificationReason = "jwt_structure_parsed_without_reliable_finding_classifier"
		}
	}
	finalizeClassifiedResult(&result)
	return result
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
