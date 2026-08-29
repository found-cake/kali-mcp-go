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

type RunStatus string

const (
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunTimeout   RunStatus = "timeout"
	RunCancelled RunStatus = "cancelled"
)

type RetryEstimate struct {
	MaximumRequests int   `json:"maximum_requests"`
	TimeoutMS       int64 `json:"timeout_ms"`
}

type FailureInfo struct {
	Code            string         `json:"code"`
	Message         string         `json:"message"`
	Retryable       bool           `json:"retryable"`
	ResumeSupported bool           `json:"resume_supported"`
	RetryEstimate   *RetryEstimate `json:"retry_estimate,omitempty"`
}

type ArtifactRef struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Location  string    `json:"location"`
	ExpiresAt time.Time `json:"expires_at"`
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
	Stdout            string            `json:"stdout"`
	Stderr            string            `json:"stderr"`
	ReturnCode        int               `json:"return_code"`
	Success           bool              `json:"success"`
	TimedOut          bool              `json:"timed_out"`
	Cancelled         bool              `json:"cancelled"`
	PartialResults    bool              `json:"partial_results"`
	Status            RunStatus         `json:"status"`
	ExecutionStatus   ExecutionStatus   `json:"execution_status"`
	FindingStatus     FindingStatus     `json:"finding_status"`
	HTTPRequests      *int              `json:"http_requests"`
	DurationMS        int64             `json:"duration_ms"`
	Failure           *FailureInfo      `json:"failure"`
	Execution         ExecutionMetadata `json:"execution"`
	Target            *TargetProvenance `json:"target"`
	SPABaseline       *SPABaseline      `json:"spa_baseline"`
	FalsePositiveRisk string            `json:"false_positive_risk"`
	Warnings          []string          `json:"warnings,omitempty"`
	Artifacts         []ArtifactRef     `json:"artifacts"`
}

func (r *ToolResult) Finalize() {
	r.Success = r.ExecutionStatus == ExecutionSucceeded
	r.TimedOut = r.ExecutionStatus == ExecutionTimedOut
	r.Cancelled = r.ExecutionStatus == ExecutionCancelled
	switch r.ExecutionStatus {
	case ExecutionSucceeded:
		r.Status = RunCompleted
	case ExecutionTimedOut:
		r.Status = RunTimeout
	case ExecutionCancelled:
		r.Status = RunCancelled
	default:
		r.Status = RunFailed
	}
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
		if r.PartialResults || r.Stdout != "" || r.Stderr != "" {
			sb.WriteString("\n\n[WARNING: timed out — partial results above]")
		} else {
			sb.WriteString("[WARNING: timed out with no output]")
		}
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
