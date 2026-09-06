package dto

type NucleiPreviewMetadata struct {
	TemplatesMatched         int    `json:"templates_matched"`
	SelectionSource          string `json:"selection_source"`
	TargetRequestsSent       int    `json:"target_requests_sent"`
	RequestEstimateAvailable bool   `json:"request_estimate_available"`
	RequestEstimateReason    string `json:"request_estimate_reason"`
}

type NucleiRuntimeMetadata struct {
	Requests  int     `json:"requests"`
	Errors    int     `json:"errors"`
	Hosts     int     `json:"hosts"`
	Matched   int     `json:"matched"`
	Templates int     `json:"templates"`
	Total     int     `json:"total"`
	Percent   float64 `json:"percent"`
	Duration  string  `json:"duration,omitempty"`
	StartedAt string  `json:"started_at,omitempty"`
}
