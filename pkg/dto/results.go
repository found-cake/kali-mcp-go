package dto

import (
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type ExecutionStatus string

const (
	ExecutionSucceeded ExecutionStatus = "succeeded"
	ExecutionFailed    ExecutionStatus = "failed"
	ExecutionTimedOut  ExecutionStatus = "timed_out"
	ExecutionCancelled ExecutionStatus = "cancelled"
)

func ExecutionStatusFromResult(returnCode int, timedOut, cancelled bool) ExecutionStatus {
	switch {
	case timedOut:
		return ExecutionTimedOut
	case cancelled:
		return ExecutionCancelled
	case returnCode != 0:
		return ExecutionFailed
	default:
		return ExecutionSucceeded
	}
}

type FindingStatus string

const (
	FindingsDetected    FindingStatus = "detected"
	FindingsNotDetected FindingStatus = "not_detected"
	FindingsUnknown     FindingStatus = "unknown"
)

type RequestCountSource string

const (
	RequestCountMeasured RequestCountSource = "measured"
	RequestCountParsed   RequestCountSource = "parsed"
	RequestCountUnknown  RequestCountSource = "unknown"
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
	Tool            string                 `json:"tool"`
	ToolVersion     string                 `json:"tool_version"`
	ArgvRedacted    []string               `json:"argv_redacted"`
	StartedAt       time.Time              `json:"started_at"`
	EndedAt         time.Time              `json:"ended_at"`
	TimeoutMS       int64                  `json:"timeout_ms"`
	Profile         SafetyProfile          `json:"profile"`
	MaxRequests     int                    `json:"max_requests"`
	RateLimit       int                    `json:"rate_limit"`
	Concurrency     int                    `json:"concurrency"`
	HealthURL       string                 `json:"health_url"`
	Max5xxResponses int                    `json:"max_5xx_responses"`
	Controls        ScanControlApplication `json:"controls"`
}

type ScanControlApplication struct {
	RequestedRateLimit   int `json:"requested_rate_limit"`
	AppliedRateLimit     int `json:"applied_rate_limit"`
	RequestedConcurrency int `json:"requested_concurrency"`
	AppliedConcurrency   int `json:"applied_concurrency"`
}

type HTTPResponseMetadata struct {
	StatusCode    int         `json:"status_code"`
	Headers       http.Header `json:"headers"`
	FinalURL      string      `json:"final_url"`
	ContentLength int64       `json:"content_length"`
	BodyBytes     int         `json:"body_bytes"`
	BodyEncoding  string      `json:"body_encoding"`
	BodyTruncated bool        `json:"body_truncated"`
}

type ToolResult struct {
	CallID               string                `json:"call_id"`
	Stdout               string                `json:"stdout"`
	Stderr               string                `json:"stderr"`
	StdoutBytes          int                   `json:"stdout_bytes"`
	StderrBytes          int                   `json:"stderr_bytes"`
	OutputTruncated      bool                  `json:"output_truncated"`
	ReturnCode           int                   `json:"return_code"`
	Success              bool                  `json:"success"`
	TimedOut             bool                  `json:"timed_out"`
	Cancelled            bool                  `json:"cancelled"`
	PartialResults       bool                  `json:"partial_results"`
	Status               RunStatus             `json:"status"`
	ExecutionStatus      ExecutionStatus       `json:"execution_status"`
	FindingStatus        FindingStatus         `json:"finding_status"`
	ClassificationReason string                `json:"classification_reason,omitempty"`
	HTTPRequests         *int                  `json:"http_requests"`
	RequestCountSource   RequestCountSource    `json:"request_count_source"`
	DurationMS           int64                 `json:"duration_ms"`
	Failure              *FailureInfo          `json:"failure"`
	Execution            ExecutionMetadata     `json:"execution"`
	Target               *TargetProvenance     `json:"target"`
	SPABaseline          *SPABaseline          `json:"spa_baseline"`
	FalsePositiveRisk    string                `json:"false_positive_risk"`
	Warnings             []string              `json:"warnings,omitempty"`
	Artifacts            []ArtifactRef         `json:"artifacts"`
	HTTPResponse         *HTTPResponseMetadata `json:"http_response,omitempty"`
	Progress             *ProgressMetadata     `json:"progress,omitempty"`
}

func (r ToolResult) Compact(maximumBytes int) ToolResult {
	r.StdoutBytes = len(r.Stdout)
	r.StderrBytes = len(r.Stderr)
	stdout, stdoutTruncated := compactUTF8(r.Stdout, maximumBytes)
	stderr, stderrTruncated := compactUTF8(r.Stderr, maximumBytes)
	r.Stdout = stdout
	r.Stderr = stderr
	r.OutputTruncated = stdoutTruncated || stderrTruncated
	return r
}

func compactUTF8(value string, maximumBytes int) (string, bool) {
	if maximumBytes < 0 || len(value) <= maximumBytes {
		return value, false
	}
	end := maximumBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true
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
	if r.RequestCountSource == "" {
		r.RequestCountSource = RequestCountUnknown
	}
	if !r.Success && !r.PartialResults {
		r.PartialResults = r.Stdout != "" || r.HTTPRequests != nil || r.Progress != nil && r.Progress.ObservedOutputItems > 0
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
	if r.OutputTruncated {
		sb.WriteString("\n\n[output truncated — read the result artifact for full redacted output]")
	}
	if sb.Len() == 0 {
		sb.WriteString("(no output)")
	}
	return sb.String()
}

type HealthResult struct {
	CallID                     string          `json:"call_id"`
	Status                     string          `json:"status"`
	Message                    string          `json:"message"`
	ToolsStatus                map[string]bool `json:"tools_status"`
	AllEssentialToolsAvailable bool            `json:"all_essential_tools_available"`
}
