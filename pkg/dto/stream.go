package dto

type StreamEvent struct {
	Stream       string            `json:"stream,omitempty"`
	Line         string            `json:"line,omitempty"`
	Heartbeat    bool              `json:"heartbeat,omitempty"`
	Done         bool              `json:"done,omitempty"`
	ReturnCode   *int              `json:"return_code,omitempty"`
	TimedOut     bool              `json:"timed_out,omitempty"`
	Cancelled    bool              `json:"cancelled,omitempty"`
	Error        string            `json:"error,omitempty"`
	HTTPRequests *int              `json:"http_requests"`
	DurationMS   int64             `json:"duration_ms,omitempty"`
	Failure      *FailureInfo      `json:"failure,omitempty"`
	Execution    ExecutionMetadata `json:"execution,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
}
