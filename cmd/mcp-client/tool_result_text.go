package main

import "github.com/found-cake/kali-mcp-go/pkg/dto"

func formatToolResultText(toolName string, result dto.ToolResult) string {
	if toolName != "jwt_analyze" || result.ExecutionStatus != dto.ExecutionSucceeded || result.JWTAnalysis == nil || result.JWTAnalysis.ParseStatus != dto.JWTParsed {
		return result.Format()
	}
	inline := result
	inline.Stdout = ""
	inline.Stderr = ""
	return inline.Format()
}
