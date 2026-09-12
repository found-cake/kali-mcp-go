package dto

type DiscoveredPath struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code,omitempty"`
	ResponseBytes int    `json:"response_bytes,omitempty"`
	Directory     bool   `json:"directory"`
}
