package dto

type NucleiPreviewMetadata struct {
	TemplatesMatched         int    `json:"templates_matched"`
	SelectionSource          string `json:"selection_source"`
	TargetRequestsSent       int    `json:"target_requests_sent"`
	RequestEstimateAvailable bool   `json:"request_estimate_available"`
	RequestEstimateReason    string `json:"request_estimate_reason"`
}
