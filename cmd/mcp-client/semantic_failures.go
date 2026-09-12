package main

import (
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func semanticToolFailure(toolName string, result dto.ToolResult, output string) *dto.FailureInfo {
	switch toolName {
	case "nmap_scan":
		if strings.Contains(output, "no targets were specified") || strings.Contains(output, "0 ip addresses (0 hosts up) scanned") {
			return semanticFailureInfo("nmap_no_targets", "Nmap did not receive a valid network target", false)
		}
	case "nuclei_scan":
		if runtime := result.NucleiRuntime; runtime != nil && runtime.Errors > 0 && (runtime.Requests == 0 || runtime.Errors >= runtime.Requests) {
			return semanticFailureInfo("nuclei_requests_failed", "Nuclei could not complete any target requests", true)
		}
	case "nikto_scan":
		if containsAny(output, "[fail] unable to connect", "no web server found", "cannot connect to") {
			return semanticFailureInfo("nikto_connection_failed", "Nikto could not connect to the target", true)
		}
	case "metasploit_run":
		if containsAny(output, "failed to load module", "exploit failed", "auxiliary failed", "one or more options failed to validate", "unknown command:") {
			return semanticFailureInfo("metasploit_execution_failed", "Metasploit reported that the requested module or action failed", false)
		}
	case "feroxbuster_scan":
		_, initialTargets, connectionErrors, hasStats := parseFeroxbusterRuntimeStatistics(result.Stdout + "\n" + result.Stderr)
		if strings.Contains(output, "could not connect to any target") || hasStats && initialTargets == 0 && connectionErrors > 0 {
			return semanticFailureInfo("feroxbuster_target_unreachable", "Feroxbuster could not connect to any target", true)
		}
	}
	return nil
}

func semanticFailureInfo(code, message string, retryable bool) *dto.FailureInfo {
	return &dto.FailureInfo{Code: code, Message: message, Retryable: retryable}
}

func containsAny(value string, signatures ...string) bool {
	for _, signature := range signatures {
		if strings.Contains(value, signature) {
			return true
		}
	}
	return false
}
