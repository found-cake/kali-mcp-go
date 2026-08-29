package dto

import (
	"strings"
	"time"
)

type ExecutionStatus string

const (
	ExecutionSucceeded ExecutionStatus = "succeeded"
	ExecutionFailed    ExecutionStatus = "failed"
	ExecutionTimedOut  ExecutionStatus = "timed_out"
	ExecutionCancelled ExecutionStatus = "cancelled"
)

type FindingStatus string

const (
	FindingsDetected    FindingStatus = "detected"
	FindingsNotDetected FindingStatus = "not_detected"
	FindingsUnknown     FindingStatus = "unknown"
)

type FailureInfo struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	Retryable       bool   `json:"retryable"`
	ResumeSupported bool   `json:"resume_supported"`
}

type ExecutionMetadata struct {
	Tool            string        `json:"tool"`
	ToolVersion     string        `json:"tool_version"`
	ArgvRedacted    []string      `json:"argv_redacted"`
	StartedAt       time.Time     `json:"started_at"`
	TimeoutMS       int64         `json:"timeout_ms"`
	Profile         SafetyProfile `json:"profile"`
	MaxRequests     int           `json:"max_requests"`
	RateLimit       int           `json:"rate_limit"`
	Concurrency     int           `json:"concurrency"`
	HealthURL       string        `json:"health_url"`
	Max5xxResponses int           `json:"max_5xx_responses"`
}

type ToolResult struct {
	Stdout          string            `json:"stdout"`
	Stderr          string            `json:"stderr"`
	ReturnCode      int               `json:"return_code"`
	Success         bool              `json:"success"`
	TimedOut        bool              `json:"timed_out"`
	Cancelled       bool              `json:"cancelled"`
	PartialResults  bool              `json:"partial_results"`
	ExecutionStatus ExecutionStatus   `json:"execution_status"`
	FindingStatus   FindingStatus     `json:"finding_status"`
	HTTPRequests    *int              `json:"http_requests"`
	DurationMS      int64             `json:"duration_ms"`
	Failure         *FailureInfo      `json:"failure"`
	Execution       ExecutionMetadata `json:"execution"`
	Target          *TargetProvenance `json:"target"`
	Warnings        []string          `json:"warnings,omitempty"`
}

func (r *ToolResult) Finalize() {
	r.Success = r.ExecutionStatus == ExecutionSucceeded
	r.TimedOut = r.ExecutionStatus == ExecutionTimedOut
	r.Cancelled = r.ExecutionStatus == ExecutionCancelled
	if r.Success {
		r.Failure = nil
	}
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
