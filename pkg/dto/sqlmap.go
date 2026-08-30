package dto

type SQLMapParameterStatus string

const (
	SQLMapParameterDetected     SQLMapParameterStatus = "detected"
	SQLMapParameterNotDetected  SQLMapParameterStatus = "not_detected"
	SQLMapParameterInconclusive SQLMapParameterStatus = "inconclusive"
)

type SQLMapParameterResult struct {
	Name   string                `json:"name"`
	Status SQLMapParameterStatus `json:"status"`
}

type SQLMapAnalysis struct {
	TrafficAvailable              bool                    `json:"traffic_available"`
	HTTPRequests                  int                     `json:"http_requests"`
	HTTPResponses                 int                     `json:"http_responses"`
	StatusCounts                  map[string]int          `json:"status_counts"`
	ServerErrorResponses          int                     `json:"server_error_responses"`
	ServerErrorRatio              float64                 `json:"server_error_ratio"`
	ResponseBodyMinBytes          int                     `json:"response_body_min_bytes"`
	ResponseBodyMaxBytes          int                     `json:"response_body_max_bytes"`
	ResponseBodyDeltaBytes        int                     `json:"response_body_delta_bytes"`
	DistinctResponseBodies        int                     `json:"distinct_response_bodies"`
	SignificantResponseDifference bool                    `json:"significant_response_difference"`
	Parameters                    []SQLMapParameterResult `json:"parameters"`
	ManualVerificationRecommended bool                    `json:"manual_verification_recommended"`
	ManualVerificationReasons     []string                `json:"manual_verification_reasons,omitempty"`
}
