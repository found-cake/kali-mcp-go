package dto

type SPABaseline struct {
	Samples       int    `json:"samples"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	BodyHash      string `json:"body_hash"`
	Stable        bool   `json:"stable"`
}
