package main

import (
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const nucleiInlineOutputBytes = 2 * 1024

func compactToolResult(toolName string, result dto.ToolResult) dto.ToolResult {
	result.ArtifactComplete = result.ArtifactComplete || completeResultArtifactAvailable(result)
	if toolName != "nuclei_scan" {
		result = result.Compact(defaultInlineOutputBytes)
		return annotateOutputCompleteness(result)
	}
	result.StdoutBytes = max(result.StdoutBytes, len(result.Stdout))
	result.StderrBytes = max(result.StderrBytes, len(result.Stderr))
	stdout, stdoutTruncated := completeLinePreview(result.Stdout, nucleiInlineOutputBytes)
	stderr, stderrTruncated := completeLinePreview(result.Stderr, nucleiInlineOutputBytes)
	result.Stdout = stdout
	result.Stderr = stderr
	result.StdoutTruncated = result.StdoutTruncated || stdoutTruncated
	result.StderrTruncated = result.StderrTruncated || stderrTruncated
	result.OutputTruncated = result.OutputTruncated || result.StdoutTruncated || result.StderrTruncated
	return annotateOutputCompleteness(result)
}

func annotateOutputCompleteness(result dto.ToolResult) dto.ToolResult {
	result.FindingOutputTruncated = result.StdoutTruncated
	return result
}

func completeResultArtifactAvailable(result dto.ToolResult) bool {
	if result.OutputTruncated {
		return false
	}
	for _, artifact := range result.Artifacts {
		if artifact.Relation == dto.ArtifactRelationToolResult {
			return true
		}
	}
	return false
}

func completeLinePreview(value string, maximumBytes int) (string, bool) {
	if len(value) <= maximumBytes {
		return value, false
	}
	end := strings.LastIndexByte(value[:maximumBytes], '\n')
	if end < 0 {
		return "", true
	}
	return value[:end+1], true
}
