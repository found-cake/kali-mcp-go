package dto

type NucleiPreviewMetadata struct {
	TemplatesMatched           int    `json:"templates_matched"`
	SelectionSource            string `json:"selection_source"`
	TargetRequestsSent         int    `json:"target_requests_sent"`
	RequestEstimateAvailable   bool   `json:"request_estimate_available"`
	MinimumRequestEstimate     int    `json:"minimum_request_estimate"`
	EstimatedMinimumDurationMS int64  `json:"estimated_minimum_duration_ms"`
	TimeoutLikelyInsufficient  bool   `json:"timeout_likely_insufficient"`
	RequestEstimateReason      string `json:"request_estimate_reason"`
}

type NucleiRequestCountSemantics string

const NucleiRequestsScheduled NucleiRequestCountSemantics = "scheduled_or_generated"

type NucleiRPSSemantics string

const NucleiRPSRuntimeStatistic NucleiRPSSemantics = "nuclei_runtime_statistic"

type NucleiRuntimeMetadata struct {
	Requests             int                         `json:"requests"`
	RequestsSemantics    NucleiRequestCountSemantics `json:"requests_semantics"`
	Errors               int                         `json:"errors"`
	Hosts                int                         `json:"hosts"`
	Matched              int                         `json:"matched"`
	Templates            int                         `json:"templates"`
	Total                int                         `json:"total"`
	Percent              float64                     `json:"percent"`
	Duration             string                      `json:"duration,omitempty"`
	StartedAt            string                      `json:"started_at,omitempty"`
	ReportedRPS          float64                     `json:"reported_rps,omitempty"`
	ReportedRPSSemantics NucleiRPSSemantics          `json:"reported_rps_semantics,omitempty"`
}
