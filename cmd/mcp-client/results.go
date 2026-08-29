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
	case toolName == "osv_scan" && result.ReturnCode == 1 && osvFindingStatus(result.Stdout) == dto.FindingsDetected:
		result.ExecutionStatus = dto.ExecutionSucceeded
		result.Success = true
	case result.ReturnCode != 0:
		result.ExecutionStatus = dto.ExecutionFailed
	default:
		result.ExecutionStatus = dto.ExecutionSucceeded
	}
	result.FindingStatus = dto.FindingsUnknown
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		return result
	}
	output := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	switch toolName {
	case "sqlmap_scan":
		switch {
		case strings.Contains(output, "is vulnerable"), strings.Contains(output, "identified the following injection point"):
			result.FindingStatus = dto.FindingsDetected
		case strings.Contains(output, "do not appear to be injectable"), strings.Contains(output, "does not seem to be injectable"):
			result.FindingStatus = dto.FindingsNotDetected
		}
	case "nmap_scan":
		if strings.Contains(output, "/tcp open") || strings.Contains(output, "/udp open") {
			result.FindingStatus = dto.FindingsDetected
		} else if strings.Contains(output, "nmap done:") {
			result.FindingStatus = dto.FindingsNotDetected
		}
	case "nikto_scan":
		if strings.Contains(output, "0 item(s) reported") || strings.Contains(output, "0 items reported") {
			result.FindingStatus = dto.FindingsNotDetected
		} else if strings.Contains(output, "item(s) reported") || strings.Contains(output, "items reported") {
			result.FindingStatus = dto.FindingsDetected
		}
	case "nuclei_scan", "ffuf_scan", "gobuster_scan", "feroxbuster_scan":
		if strings.TrimSpace(result.Stdout) == "" {
			result.FindingStatus = dto.FindingsNotDetected
		} else {
			result.FindingStatus = dto.FindingsDetected
		}
	case "whatweb_scan":
		if strings.TrimSpace(output) == "" || strings.Contains(output, "error opening:") {
			result.ExecutionStatus = dto.ExecutionFailed
		} else {
			result.FindingStatus = dto.FindingsDetected
		}
	case "browser_check":
		var report struct {
			Dialogs []json.RawMessage `json:"dialogs"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err == nil {
			if len(report.Dialogs) > 0 {
				result.FindingStatus = dto.FindingsDetected
			} else {
				result.FindingStatus = dto.FindingsNotDetected
			}
		}
	case "dalfox_scan":
		var report struct {
			Findings []json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err == nil {
			if len(report.Findings) > 0 {
				result.FindingStatus = dto.FindingsDetected
			} else {
				result.FindingStatus = dto.FindingsNotDetected
			}
		}
	case "retirejs_scan":
		var report struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err == nil && len(report.Data) == 0 {
			result.FindingStatus = dto.FindingsNotDetected
		} else if strings.TrimSpace(result.Stdout) != "" {
			result.FindingStatus = dto.FindingsDetected
		}
	case "osv_scan":
		if status := osvFindingStatus(result.Stdout); status != dto.FindingsUnknown {
			result.FindingStatus = status
		} else if strings.Contains(output, "no vulnerabilities found") || strings.Contains(output, "no issues found") {
			result.FindingStatus = dto.FindingsNotDetected
		}
	case "john_crack":
		if strings.Contains(output, "1g ") || strings.Contains(output, "password hash cracked") {
			result.FindingStatus = dto.FindingsDetected
		}
	}
	return result
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
