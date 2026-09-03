package dto

const CallIDHeader = "X-Kali-MCP-Call-ID"

type StreamEvent struct {
	CallID             string                 `json:"call_id,omitempty"`
	Stream             string                 `json:"stream,omitempty"`
	Line               string                 `json:"line,omitempty"`
	Heartbeat          bool                   `json:"heartbeat,omitempty"`
	Done               bool                   `json:"done,omitempty"`
	ReturnCode         *int                   `json:"return_code,omitempty"`
	TimedOut           bool                   `json:"timed_out,omitempty"`
	Cancelled          bool                   `json:"cancelled,omitempty"`
	Error              string                 `json:"error,omitempty"`
	HTTPRequests       *int                   `json:"http_requests"`
	RequestCountSource RequestCountSource     `json:"request_count_source,omitempty"`
	DurationMS         int64                  `json:"duration_ms,omitempty"`
	Failure            *FailureInfo           `json:"failure,omitempty"`
	Execution          ExecutionMetadata      `json:"execution,omitempty"`
	Target             *TargetProvenance      `json:"target,omitempty"`
	SPABaseline        *SPABaseline           `json:"spa_baseline,omitempty"`
	FalsePositiveRisk  string                 `json:"false_positive_risk,omitempty"`
	Warnings           []string               `json:"warnings,omitempty"`
	Artifacts          []ArtifactRef          `json:"artifacts,omitempty"`
	Progress           *ProgressMetadata      `json:"progress,omitempty"`
	JWTAnalysis        *JWTAnalysisMetadata   `json:"jwt_analysis,omitempty"`
	SQLMapAnalysis     *SQLMapAnalysis        `json:"sqlmap_analysis,omitempty"`
	NucleiPreview      *NucleiPreviewMetadata `json:"nuclei_preview,omitempty"`
	Evidence           *EvidenceManifest      `json:"evidence,omitempty"`
}
