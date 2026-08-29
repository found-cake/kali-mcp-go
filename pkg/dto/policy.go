package dto

type SafetyProfile string

const (
	ProfileSafeRecon           SafetyProfile = "safe-recon"
	ProfileWebDiscoveryLowRate SafetyProfile = "web-discovery-low-rate"
	ProfileSQLILowRisk         SafetyProfile = "sqli-verify-low-risk"
	ProfileBrowserXSSConfirm   SafetyProfile = "browser-xss-confirm"
	ProfileExplicitCustom      SafetyProfile = "explicit-custom"
)

type ScanOptions struct {
	ResolutionReceipt string        `json:"resolution_receipt,omitempty" jsonschema:"receipt returned by resolve_target for the selected target"`
	SessionID         string        `json:"session_id,omitempty" jsonschema:"opaque target authentication session handle"`
	Profile           SafetyProfile `json:"profile,omitempty" jsonschema:"safe-recon|web-discovery-low-rate|sqli-verify-low-risk|browser-xss-confirm|explicit-custom"`
	MaxRequests       int           `json:"max_requests,omitempty" jsonschema:"maximum HTTP requests when the selected tool can enforce it"`
	RateLimit         int           `json:"rate_limit,omitempty" jsonschema:"maximum requests per second when the selected tool can enforce it"`
	Concurrency       int           `json:"concurrency,omitempty" jsonschema:"maximum tool-level concurrency when supported"`
	HealthURL         string        `json:"health_url,omitempty" jsonschema:"optional target health URL checked before and after the scan"`
	Max5xxResponses   int           `json:"max_5xx_responses,omitempty" jsonschema:"stop threshold for observed target 5xx responses when supported"`
}

func (o ScanOptions) GetScanOptions() ScanOptions { return o }

type ScanRequest interface {
	GetScanOptions() ScanOptions
}
