package dto

type TargetInputFormat string

const (
	TargetInputNetworkHost   TargetInputFormat = "network_host"
	TargetInputWebURL        TargetInputFormat = "web_url"
	TargetInputURLOrHost     TargetInputFormat = "url_or_host"
	TargetInputURLOrFile     TargetInputFormat = "url_or_file"
	TargetInputToken         TargetInputFormat = "token"
	TargetInputOfflinePath   TargetInputFormat = "offline_path"
	TargetInputCapture       TargetInputFormat = "capture_or_pcap"
	TargetInputCommand       TargetInputFormat = "command"
	TargetInputModule        TargetInputFormat = "module_target"
	TargetInputURLListOrFile TargetInputFormat = "url_list_or_file"
)

type ScanControl string

const (
	ScanControlRateLimit   ScanControl = "rate_limit"
	ScanControlConcurrency ScanControl = "concurrency"
	ScanControlMaxRequests ScanControl = "max_requests"
	ScanControlMax5xx      ScanControl = "max_5xx_responses"
	ScanControlTimeout     ScanControl = "timeout"
	ScanControlDryRun      ScanControl = "dry_run"
)

type ControlEnforcement string

const (
	ControlNativeCLI      ControlEnforcement = "native_cli"
	ControlDerivedTimeout ControlEnforcement = "derived_timeout"
	ControlOutputObserver ControlEnforcement = "output_observer"
	ControlRequestTimeout ControlEnforcement = "request_timeout"
	ControlServerPreview  ControlEnforcement = "server_preview"
)

type ScanControlCapability struct {
	Control     ScanControl        `json:"control"`
	Enforcement ControlEnforcement `json:"enforcement"`
}

type ImpactLevel string

const (
	ImpactOffline            ImpactLevel = "offline"
	ImpactPassive            ImpactLevel = "passive"
	ImpactActive             ImpactLevel = "active"
	ImpactCredential         ImpactLevel = "credential"
	ImpactExploit            ImpactLevel = "exploit"
	ImpactArbitraryExecution ImpactLevel = "arbitrary_execution"
)

type ToolExecutionMode string

const (
	ToolExecutionPost   ToolExecutionMode = "post"
	ToolExecutionStream ToolExecutionMode = "stream"
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
	Tool                  string                  `json:"tool"`
	RuntimeTool           string                  `json:"runtime_tool"`
	Description           string                  `json:"description"`
	Endpoint              string                  `json:"endpoint"`
	TargetInputFormat     TargetInputFormat       `json:"target_input_format"`
	Profiles              []SafetyProfile         `json:"profiles"`
	SupportedControls     []ScanControl           `json:"supported_controls"`
	Controls              []ScanControlCapability `json:"controls"`
	ImpactLevel           ImpactLevel             `json:"impact_level"`
	ExecutionMode         ToolExecutionMode       `json:"execution_mode"`
	InputSchemaSource     string                  `json:"input_schema_source"`
	Available             bool                    `json:"available"`
	AvailabilityChecked   bool                    `json:"availability_checked"`
	BuiltIn               bool                    `json:"built_in"`
	Essential             bool                    `json:"essential"`
	RequiresTargetContext bool                    `json:"requires_target_context"`
	ResumeSupported       bool                    `json:"resume_supported"`
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
	CallID    string                  `json:"call_id"`
	Profiles  []ScanProfileCapability `json:"profiles"`
	Tools     []ScanToolCapability    `json:"tools"`
	Wordlists []WordlistCapability    `json:"wordlists"`
}
