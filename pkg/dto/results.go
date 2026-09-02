package dto

import (
	"net/http"
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
	FindingsDetected     FindingStatus = "detected"
	FindingsNotDetected  FindingStatus = "not_detected"
	FindingsInconclusive FindingStatus = "inconclusive"
	FindingsUnknown      FindingStatus = "unknown"
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

type TimeoutSource string

const (
	TimeoutSourceDefault       TimeoutSource = "default"
	TimeoutSourceRequest       TimeoutSource = "request"
	TimeoutSourceRequestBudget TimeoutSource = "request_budget_estimate"
)

type TimeoutPlanning struct {
	Source                  TimeoutSource `json:"source"`
	RequestBudgetEstimateMS int64         `json:"request_budget_estimate_ms"`
	StartupGraceMS          int64         `json:"startup_grace_ms"`
	MaxRequestsHardLimit    bool          `json:"max_requests_hard_limit"`
}

type ExecutionMetadata struct {
	Tool            string                 `json:"tool"`
	ToolVersion     string                 `json:"tool_version"`
	ArgvRedacted    []string               `json:"argv_redacted"`
	StartedAt       time.Time              `json:"started_at"`
	EndedAt         time.Time              `json:"ended_at"`
	TimeoutMS       int64                  `json:"timeout_ms"`
	TimeoutPlanning *TimeoutPlanning       `json:"timeout_planning,omitempty"`
	ProcessStarted  bool                   `json:"process_started"`
	GracefulStopMS  int64                  `json:"graceful_stop_ms"`
	DryRun          bool                   `json:"dry_run"`
	Profile         SafetyProfile          `json:"profile"`
	MaxRequests     int                    `json:"max_requests"`
	RateLimit       int                    `json:"rate_limit"`
	Concurrency     int                    `json:"concurrency"`
	HealthURL       string                 `json:"health_url"`
	Max5xxResponses int                    `json:"max_5xx_responses"`
	Controls        ScanControlApplication `json:"controls"`
}

type ScanControlApplication struct {
	RequestedRateLimit   int                  `json:"requested_rate_limit"`
	AppliedRateLimit     int                  `json:"applied_rate_limit"`
	RequestedConcurrency int                  `json:"requested_concurrency"`
	AppliedConcurrency   int                  `json:"applied_concurrency"`
	Controls             []AppliedScanControl `json:"controls"`
}

type AppliedScanControl struct {
	Control     ScanControl        `json:"control"`
	Requested   int                `json:"requested"`
	Effective   int                `json:"effective"`
	Applied     bool               `json:"applied"`
	Enforcement ControlEnforcement `json:"enforcement"`
}

type HTTPResponseMetadata struct {
	StatusCode    int              `json:"status_code"`
	Headers       http.Header      `json:"headers"`
	FinalURL      string           `json:"final_url"`
	ContentLength int64            `json:"content_length"`
	BodyBytes     int              `json:"body_bytes"`
	BodyEncoding  string           `json:"body_encoding"`
	BodyTruncated bool             `json:"body_truncated"`
	Summary       *HTTPBodySummary `json:"summary,omitempty"`
}

type HTTPBodySummary struct {
	BodySHA256             string   `json:"body_sha256"`
	BodyExcerpt            string   `json:"body_excerpt,omitempty"`
	BodyExcerptTruncated   bool     `json:"body_excerpt_truncated"`
	JSONKeys               []string `json:"json_keys,omitempty"`
	Location               string   `json:"location,omitempty"`
	StackTraceSuspected    bool     `json:"stack_trace_suspected"`
	SensitiveDataSuspected bool     `json:"sensitive_data_suspected"`
}

type HTTPRequestMetadata struct {
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Host            string      `json:"host,omitempty"`
	Headers         http.Header `json:"headers"`
	ContentType     string      `json:"content_type,omitempty"`
	BodyBytes       int         `json:"body_bytes"`
	BodySHA256      string      `json:"body_sha256,omitempty"`
	FollowRedirects bool        `json:"follow_redirects"`
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
	HTTPRequest          *HTTPRequestMetadata  `json:"http_request,omitempty"`
	HTTPResponse         *HTTPResponseMetadata `json:"http_response,omitempty"`
	JWTAnalysis          *JWTAnalysisMetadata  `json:"jwt_analysis,omitempty"`
	SQLMapAnalysis       *SQLMapAnalysis       `json:"sqlmap_analysis,omitempty"`
	Evidence             *EvidenceManifest     `json:"evidence,omitempty"`
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

type HealthResult struct {
	CallID                     string          `json:"call_id"`
	Status                     string          `json:"status"`
	Message                    string          `json:"message"`
	ToolsStatus                map[string]bool `json:"tools_status"`
	AllEssentialToolsAvailable bool            `json:"all_essential_tools_available"`
}
