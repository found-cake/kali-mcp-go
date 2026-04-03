package dto

import "strings"

type ToolResult struct {
	Stdout         string `json:"stdout"`
	Stderr         string `json:"stderr"`
	ReturnCode     int    `json:"return_code"`
	Success        bool   `json:"success,omitempty"`
	TimedOut       bool   `json:"timed_out"`
	PartialResults bool   `json:"partial_results,omitempty"`
}

func (r *ToolResult) Format() string {
	var sb strings.Builder
	if r.Stdout != "" {
		sb.WriteString(r.Stdout)
	}
	if r.Stderr != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n[stderr]\n")
		}
		sb.WriteString(r.Stderr)
	}
	if r.TimedOut {
		sb.WriteString("\n\n[WARNING: timed out — partial results above]")
	}
	if sb.Len() == 0 {
		sb.WriteString("(no output)")
	}
	return sb.String()
}

type HealthResult struct {
	Status                     string          `json:"status"`
	Message                    string          `json:"message"`
	ToolsStatus                map[string]bool `json:"tools_status"`
	AllEssentialToolsAvailable bool            `json:"all_essential_tools_available"`
}
