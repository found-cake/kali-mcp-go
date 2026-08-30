package dto

import "time"

type TargetScope string

const (
	TargetScopeRequested      TargetScope = "requested"
	TargetScopeKaliRuntime    TargetScope = "kali_runtime"
	TargetScopeDockerHost     TargetScope = "docker_host"
	TargetScopeDefaultGateway TargetScope = "default_gateway"
)

type TargetProbeType string

const TargetProbeTCPConnect TargetProbeType = "tcp_connect"

type TargetProbeErrorCode string

const (
	TargetProbeConnectionRefused  TargetProbeErrorCode = "connection_refused"
	TargetProbeHostUnreachable    TargetProbeErrorCode = "host_unreachable"
	TargetProbeNetworkUnreachable TargetProbeErrorCode = "network_unreachable"
	TargetProbeTimeout            TargetProbeErrorCode = "timeout"
	TargetProbeUnknown            TargetProbeErrorCode = "unknown"
)

type TargetProbeEvidence struct {
	Type      TargetProbeType      `json:"type"`
	Address   string               `json:"address"`
	Port      int                  `json:"port"`
	LatencyMS int64                `json:"latency_ms"`
	ErrorCode TargetProbeErrorCode `json:"error_code,omitempty"`
}

type TargetHTTPProbeEvidence struct {
	StatusCode int    `json:"status_code,omitempty"`
	FinalURL   string `json:"final_url,omitempty"`
	Error      string `json:"error,omitempty"`
}

type ResolveTargetRequest struct {
	Target                     string `json:"target" jsonschema:"required,target URL, host, or host:port to inspect"`
	ConnectTimeoutMilliseconds int    `json:"connect_timeout_milliseconds,omitempty" jsonschema:"TCP connect timeout per candidate in milliseconds (default 500, maximum 5000)"`
	ValidForSeconds            int    `json:"valid_for_seconds,omitempty" jsonschema:"signed context validity in seconds (default 600, maximum 3600)"`
}

type TargetCandidate struct {
	Target            string                   `json:"target"`
	BrowserTarget     string                   `json:"browser_target,omitempty"`
	NetworkTarget     string                   `json:"network_target"`
	Host              string                   `json:"host"`
	Port              int                      `json:"port,omitempty"`
	Scope             TargetScope              `json:"scope"`
	NetworkNamespace  string                   `json:"network_namespace"`
	AddressFamily     string                   `json:"address_family,omitempty"`
	ResolvedAddresses []string                 `json:"resolved_addresses,omitempty"`
	Selectable        bool                     `json:"selectable"`
	Probed            bool                     `json:"probed"`
	Reachable         bool                     `json:"reachable"`
	ProbeError        string                   `json:"probe_error,omitempty"`
	Probe             *TargetProbeEvidence     `json:"probe,omitempty"`
	HTTPProbe         *TargetHTTPProbeEvidence `json:"http_probe,omitempty"`
	TargetContext     string                   `json:"target_context,omitempty"`
	ContextExpiresAt  time.Time                `json:"context_expires_at,omitempty"`
}

type TargetResolutionResult struct {
	CallID                   string            `json:"call_id"`
	OriginalTarget           string            `json:"original_target"`
	Loopback                 bool              `json:"loopback"`
	Candidates               []TargetCandidate `json:"candidates"`
	RecommendedTarget        string            `json:"recommended_target,omitempty"`
	RecommendedBrowserTarget string            `json:"recommended_browser_target,omitempty"`
	RecommendedNetworkTarget string            `json:"recommended_network_target,omitempty"`
	RecommendedNetworkPort   int               `json:"recommended_network_port,omitempty"`
	ResolutionID             string            `json:"resolution_id,omitempty"`
	ResolutionReceipt        string            `json:"resolution_receipt,omitempty"`
	ReceiptExpiresAt         time.Time         `json:"receipt_expires_at,omitempty"`
	RecommendationBasis      string            `json:"recommendation_basis,omitempty"`
	Warnings                 []string          `json:"warnings,omitempty"`
}

type TargetProvenance struct {
	Original         string      `json:"original"`
	Selected         string      `json:"selected"`
	ResolutionID     string      `json:"resolution_id,omitempty"`
	SelectionReason  string      `json:"selection_reason"`
	Verified         bool        `json:"verified"`
	Scope            TargetScope `json:"scope,omitempty"`
	Port             int         `json:"port,omitempty"`
	ContextExpiresAt time.Time   `json:"context_expires_at,omitempty"`
	ExpiresInSeconds int64       `json:"expires_in_seconds,omitempty"`
	ExpiringSoon     bool        `json:"expiring_soon,omitempty"`
}
