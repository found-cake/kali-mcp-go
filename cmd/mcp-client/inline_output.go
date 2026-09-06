package main

import (
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const nucleiInlineOutputBytes = 2 * 1024

func compactToolResult(toolName string, result dto.ToolResult) dto.ToolResult {
	if toolName != "nuclei_scan" {
		return result.Compact(defaultInlineOutputBytes)
	}
	result.StdoutBytes = len(result.Stdout)
	result.StderrBytes = len(result.Stderr)
	stdout, stdoutTruncated := completeLinePreview(result.Stdout, nucleiInlineOutputBytes)
	stderr, stderrTruncated := completeLinePreview(result.Stderr, nucleiInlineOutputBytes)
	result.Stdout = stdout
	result.Stderr = stderr
	result.OutputTruncated = result.OutputTruncated || stdoutTruncated || stderrTruncated
	return result
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
