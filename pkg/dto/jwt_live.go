package dto

type JWTHTTPStatusCount struct {
	StatusCode int `json:"status_code"`
	Count      int `json:"count"`
}

type JWTLiveAnalysisMetadata struct {
	Completed             bool                 `json:"completed"`
	BaselineAccepted      bool                 `json:"baseline_accepted"`
	Requests              int                  `json:"requests"`
	BaselineRequests      int                  `json:"baseline_requests"`
	ControlsTested        int                  `json:"controls_tested"`
	ControlsAccepted      int                  `json:"controls_accepted"`
	ControlsRejected      int                  `json:"controls_rejected"`
	ControlsInconclusive  int                  `json:"controls_inconclusive"`
	MutationsTested       int                  `json:"mutations_tested"`
	MutationsAccepted     int                  `json:"mutations_accepted"`
	MutationsRejected     int                  `json:"mutations_rejected"`
	MutationsInconclusive int                  `json:"mutations_inconclusive"`
	StatusCodes           []JWTHTTPStatusCount `json:"status_codes,omitempty"`
}
