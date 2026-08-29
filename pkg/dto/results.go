package dto

import "strings"

type ExecutionStatus string

const (
	ExecutionSucceeded ExecutionStatus = "succeeded"
	ExecutionFailed    ExecutionStatus = "failed"
	ExecutionTimedOut  ExecutionStatus = "timed_out"
)

type FindingStatus string

const (
	FindingsDetected    FindingStatus = "detected"
	FindingsNotDetected FindingStatus = "not_detected"
	FindingsUnknown     FindingStatus = "unknown"
)

type ToolResult struct {
	Stdout          string          `json:"stdout"`
	Stderr          string          `json:"stderr"`
	ReturnCode      int             `json:"return_code"`
	Success         bool            `json:"success"`
	TimedOut        bool            `json:"timed_out"`
	PartialResults  bool            `json:"partial_results,omitempty"`
	ExecutionStatus ExecutionStatus `json:"execution_status"`
	FindingStatus   FindingStatus   `json:"finding_status"`
	HTTPRequests    int             `json:"http_requests,omitempty"`
	Warnings        []string        `json:"warnings,omitempty"`
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
