package dto

type StreamEvent struct {
	Stream     string `json:"stream,omitempty"`
	Line       string `json:"line,omitempty"`
	Heartbeat  bool   `json:"heartbeat,omitempty"`
	Done       bool   `json:"done,omitempty"`
	ReturnCode *int   `json:"return_code,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	Error      string `json:"error,omitempty"`
}
