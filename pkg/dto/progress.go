package dto

type ProgressPhase string

const (
	ProgressRunning   ProgressPhase = "running"
	ProgressCompleted ProgressPhase = "completed"
	ProgressFailed    ProgressPhase = "failed"
	ProgressTimedOut  ProgressPhase = "timed_out"
	ProgressCancelled ProgressPhase = "cancelled"
)

type ProgressMetadata struct {
	Phase               ProgressPhase `json:"phase"`
	ObservedOutputItems int           `json:"observed_output_items"`
	LastObservedOutput  string        `json:"last_observed_output,omitempty"`
	HTTPRequests        *int          `json:"http_requests"`
	HTTPRequestBudget   int           `json:"http_request_budget"`
	Checkpoint          string        `json:"checkpoint,omitempty"`
	ResumeSupported     bool          `json:"resume_supported"`
}
