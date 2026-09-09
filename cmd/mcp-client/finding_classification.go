package main

import (
	"encoding/json"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func classifySuccessfulFinding(toolName string, result *dto.ToolResult, output string) {
	switch toolName {
	case "sqlmap_scan":
		classifySQLMapFinding(result, output)
	case "nmap_scan":
		if strings.Contains(output, "/tcp open") || strings.Contains(output, "/udp open") {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "nmap_open_port_reported"
		} else if strings.Contains(output, "nmap done:") {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "nmap_completed_without_open_port"
		}
	case "nikto_scan":
		classifyNiktoFinding(result, output)
	case "gobuster_scan":
		if gobusterReportedFinding(result.Stdout) {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "gobuster_result_reported"
		} else {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "gobuster_completed_without_result"
		}
	case "dirb_scan":
		if len(result.DiscoveredPaths) > 0 {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "dirb_paths_reported"
		} else {
			result.FindingStatus = dto.FindingsNotDetected
			result.ClassificationReason = "dirb_completed_without_result"
		}
	case "nuclei_scan":
		classifyNucleiFinding(result)
	case "ffuf_scan":
		classifyFFUFFinding(result)
	case "feroxbuster_scan":
		classifyFeroxbusterFinding(result, output)
	case "whatweb_scan":
		if strings.TrimSpace(output) == "" || strings.Contains(output, "error opening:") {
			result.ExecutionStatus = dto.ExecutionFailed
			result.ClassificationReason = "whatweb_reported_open_error"
		} else {
			result.FindingStatus = dto.FindingsDetected
			result.ClassificationReason = "whatweb_fingerprint_reported"
		}
	case "browser_check":
		classifyBrowserFinding(result)
	case "dalfox_scan":
		classifyDalfoxFinding(result)
	case "retirejs_scan":
		classifyRetireFinding(result)
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
			if result.JWTLiveAnalysis != nil {
				classifyJWTLiveFinding(result)
			} else if strings.Contains(output, "cannot find a valid jwt") {
				result.FindingStatus = dto.FindingsInconclusive
				result.PartialResults = true
				result.ClassificationReason = "jwt_live_token_not_observed"
			} else {
				result.ClassificationReason = "jwt_structure_parsed_without_reliable_finding_classifier"
			}
		}
	}
}

func classifySQLMapFinding(result *dto.ToolResult, output string) {
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
}

func classifyNiktoFinding(result *dto.ToolResult, output string) {
	if strings.Contains(output, "0 item(s) reported") || strings.Contains(output, "0 items reported") {
		result.FindingStatus = dto.FindingsNotDetected
		result.ClassificationReason = "nikto_zero_items_reported"
	} else if strings.Contains(output, "item(s) reported") || strings.Contains(output, " item reported") || strings.Contains(output, " items reported") {
		result.FindingStatus = dto.FindingsDetected
		result.ClassificationReason = "nikto_items_reported"
	}
}

func classifyNucleiFinding(result *dto.ToolResult) {
	partial := result.NucleiRuntime != nil && result.NucleiRuntime.Errors > 0
	finding, malformed := classifyNucleiOutput(result.Stdout)
	switch {
	case finding:
		result.FindingStatus = dto.FindingsDetected
		if partial {
			result.PartialResults = true
			result.ClassificationReason = "nuclei_partial_finding_reported"
		} else {
			result.ClassificationReason = "scanner_emitted_findings"
		}
	case partial:
		result.FindingStatus = dto.FindingsInconclusive
		result.PartialResults = true
		result.ClassificationReason = "nuclei_partial_request_errors"
	case malformed:
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "nuclei_output_not_valid_jsonl"
	default:
		result.FindingStatus = dto.FindingsNotDetected
		result.ClassificationReason = "scanner_completed_without_output"
	}
}

func classifyFFUFFinding(result *dto.ToolResult) {
	if strings.TrimSpace(result.Stdout) == "" {
		result.FindingStatus = dto.FindingsNotDetected
		result.ClassificationReason = "scanner_completed_without_output"
	} else if ffufReportedFinding(result.Stdout) {
		result.FindingStatus = dto.FindingsDetected
		result.ClassificationReason = "scanner_emitted_findings"
	} else {
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "ffuf_output_not_valid_jsonl"
	}
}

func classifyFeroxbusterFinding(result *dto.ToolResult, _ string) {
	errors, _, _, hasStats := parseFeroxbusterRuntimeStatistics(result.Stdout + "\n" + result.Stderr)
	if len(result.DiscoveredPaths) > 0 {
		result.FindingStatus = dto.FindingsDetected
		if hasStats && errors > 0 {
			result.PartialResults = true
			result.ClassificationReason = "feroxbuster_partial_finding_reported"
		} else {
			result.ClassificationReason = "scanner_emitted_findings"
		}
	} else if hasStats && errors > 0 {
		result.FindingStatus = dto.FindingsInconclusive
		result.PartialResults = true
		result.ClassificationReason = "feroxbuster_partial_request_errors"
	} else {
		result.FindingStatus = dto.FindingsNotDetected
		result.ClassificationReason = "scanner_completed_without_findings"
	}
}

func classifyBrowserFinding(result *dto.ToolResult) {
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
		return
	}
	result.ExecutionStatus = dto.ExecutionFailed
	result.ClassificationReason = "browser_report_invalid_json"
	result.Failure = &dto.FailureInfo{Code: "output_parse_failed", Message: "browser output is not valid JSON"}
}

func classifyDalfoxFinding(result *dto.ToolResult) {
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err != nil {
		return
	}
	if len(report.Findings) > 0 {
		result.FindingStatus = dto.FindingsDetected
		result.ClassificationReason = "dalfox_findings_reported"
	} else {
		result.FindingStatus = dto.FindingsNotDetected
		result.ClassificationReason = "dalfox_zero_findings_reported"
	}
}

func classifyRetireFinding(result *dto.ToolResult) {
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
}
