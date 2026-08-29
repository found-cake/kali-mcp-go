package dto

import "time"

type TargetScope string

const (
	TargetScopeRequested      TargetScope = "requested"
	TargetScopeKaliRuntime    TargetScope = "kali_runtime"
	TargetScopeDockerHost     TargetScope = "docker_host"
	TargetScopeDefaultGateway TargetScope = "default_gateway"
)

type ResolveTargetRequest struct {
	Target                     string `json:"target" jsonschema:"required,target URL, host, or host:port to inspect"`
	ConnectTimeoutMilliseconds int    `json:"connect_timeout_milliseconds,omitempty" jsonschema:"TCP connect timeout per candidate in milliseconds (default 500, maximum 5000)"`
}

type TargetCandidate struct {
	Target            string      `json:"target"`
	Host              string      `json:"host"`
	Port              int         `json:"port,omitempty"`
	Scope             TargetScope `json:"scope"`
	ResolvedAddresses []string    `json:"resolved_addresses,omitempty"`
	Probed            bool        `json:"probed"`
	Reachable         bool        `json:"reachable"`
	ProbeError        string      `json:"probe_error,omitempty"`
}

type TargetResolutionResult struct {
	OriginalTarget      string            `json:"original_target"`
	Loopback            bool              `json:"loopback"`
	Candidates          []TargetCandidate `json:"candidates"`
	RecommendedTarget   string            `json:"recommended_target,omitempty"`
	ResolutionID        string            `json:"resolution_id,omitempty"`
	ResolutionReceipt   string            `json:"resolution_receipt,omitempty"`
	ReceiptExpiresAt    time.Time         `json:"receipt_expires_at,omitempty"`
	RecommendationBasis string            `json:"recommendation_basis,omitempty"`
	Warnings            []string          `json:"warnings,omitempty"`
}

type TargetProvenance struct {
	Original        string `json:"original"`
	Selected        string `json:"selected"`
	ResolutionID    string `json:"resolution_id,omitempty"`
	SelectionReason string `json:"selection_reason"`
	Verified        bool   `json:"verified"`
}
