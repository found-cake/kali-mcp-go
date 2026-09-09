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
	TargetContext     string        `json:"target_context,omitempty" jsonschema:"signed candidate context returned by resolve_target; use instead of target plus resolution_receipt"`
	Profile           SafetyProfile `json:"profile,omitempty" jsonschema:"safe-recon|web-discovery-low-rate|sqli-verify-low-risk|browser-xss-confirm|explicit-custom"`
	RateLimit         int           `json:"rate_limit,omitempty" jsonschema:"requests-per-second value passed to the tool's native limiter; 0 means unset, not unlimited"`
	Concurrency       int           `json:"concurrency,omitempty" jsonschema:"maximum tool-level concurrency when supported; 0 means unset, not unlimited"`
	HealthURL         string        `json:"health_url,omitempty" jsonschema:"optional same-service target health URL checked before and after the scan; cross-origin redirects are rejected"`
	Max5xxResponses   int           `json:"max_5xx_responses,omitempty" jsonschema:"stop threshold for observed target 5xx responses when the selected tool supports it; 0 means unset or unsupported, not unlimited"`
	RedactValues      []string      `json:"redact_values,omitempty" jsonschema:"optional exact values to replace in output and artifacts; all other content is preserved verbatim"`
}

func (o ScanOptions) GetScanOptions() ScanOptions { return o }

type ScanRequest interface {
	GetScanOptions() ScanOptions
}
