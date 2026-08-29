package dto

type TargetInputFormat string

const (
	TargetInputNetworkHost TargetInputFormat = "network_host"
	TargetInputWebURL      TargetInputFormat = "web_url"
	TargetInputURLOrHost   TargetInputFormat = "url_or_host"
	TargetInputURLOrFile   TargetInputFormat = "url_or_file"
	TargetInputToken       TargetInputFormat = "token"
)

type ScanControl string

const (
	ScanControlRateLimit   ScanControl = "rate_limit"
	ScanControlConcurrency ScanControl = "concurrency"
)

type ScanLimits struct {
	MaxRequests     int `json:"max_requests"`
	RateLimit       int `json:"rate_limit"`
	Concurrency     int `json:"concurrency"`
	Max5xxResponses int `json:"max_5xx_responses"`
}

type ScanProfileCapability struct {
	Profile SafetyProfile `json:"profile"`
	Tools   []string      `json:"tools"`
	Limits  ScanLimits    `json:"limits"`
}

type ScanToolCapability struct {
	Tool              string            `json:"tool"`
	RuntimeTool       string            `json:"runtime_tool"`
	TargetInputFormat TargetInputFormat `json:"target_input_format"`
	Profiles          []SafetyProfile   `json:"profiles"`
	SupportedControls []ScanControl     `json:"supported_controls"`
}

type WordlistCapability struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Purpose    string   `json:"purpose"`
	Available  bool     `json:"available"`
	SizeBytes  int64    `json:"size_bytes"`
	DefaultFor []string `json:"default_for"`
}

type ScanCapabilitiesResult struct {
	Profiles  []ScanProfileCapability `json:"profiles"`
	Tools     []ScanToolCapability    `json:"tools"`
	Wordlists []WordlistCapability    `json:"wordlists"`
}
