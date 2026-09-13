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
	ScanControlMax5xx      ScanControl = "max_5xx_responses"
	ScanControlTimeout     ScanControl = "timeout"
	ScanControlDryRun      ScanControl = "dry_run"
)

type ControlEnforcement string

const (
	ControlNativeCLI        ControlEnforcement = "native_cli"
	ControlNativeCLIAverage ControlEnforcement = "native_cli_average_bursty"
	ControlOutputObserver   ControlEnforcement = "output_observer"
	ControlRequestTimeout   ControlEnforcement = "request_timeout"
	ControlServerPreview    ControlEnforcement = "server_preview"
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
	RateLimit       int `json:"rate_limit" jsonschema:"profile ceiling for tools whose supported_controls include rate_limit; not a guaranteed applied default"`
	Concurrency     int `json:"concurrency" jsonschema:"profile ceiling for tools whose supported_controls include concurrency; not a guaranteed applied default"`
	Max5xxResponses int `json:"max_5xx_responses" jsonschema:"profile ceiling for tools whose supported_controls include max_5xx_responses; not a guaranteed applied default"`
}

type ScanProfileCapability struct {
	Profile SafetyProfile `json:"profile"`
	Tools   []string      `json:"tools"`
	Limits  ScanLimits    `json:"limits" jsonschema:"profile ceilings; inspect each tool's supported_controls and execution.controls for actual applicability"`
}

type PluginRiskHint string

const (
	PluginRiskTargetStateChange      PluginRiskHint = "target_state_change"
	PluginRiskLargeSensitiveResponse PluginRiskHint = "potentially_large_sensitive_response"
	PluginRiskHighRequestCount       PluginRiskHint = "high_request_count"
	PluginRiskNonstandardHTTPMethods PluginRiskHint = "nonstandard_http_methods"
	PluginRiskActiveExploitProbe     PluginRiskHint = "active_exploit_probe"
)

type ToolPluginCapability struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	RiskHints   []PluginRiskHint `json:"risk_hints,omitempty"`
}

type ToolPluginInventory struct {
	Source            string                 `json:"source"`
	Available         bool                   `json:"available"`
	RuntimeVersion    string                 `json:"runtime_version,omitempty"`
	RiskHintsComplete bool                   `json:"risk_hints_complete"`
	Plugins           []ToolPluginCapability `json:"plugins"`
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
	InputSchemaJSON       string                  `json:"input_schema_json,omitempty"`
	Available             bool                    `json:"available"`
	AvailabilityChecked   bool                    `json:"availability_checked"`
	BuiltIn               bool                    `json:"built_in"`
	Essential             bool                    `json:"essential"`
	RequiresTargetContext bool                    `json:"requires_target_context"`
	ResumeSupported       bool                    `json:"resume_supported"`
	PluginInventory       *ToolPluginInventory    `json:"plugin_inventory,omitempty"`
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

type ScanCapabilitiesRequest struct {
	ToolName  string   `json:"tool_name,omitempty" jsonschema:"optional executable MCP tool name used to return one compact tool capability; mutually exclusive with tool_names"`
	ToolNames []string `json:"tool_names,omitempty" jsonschema:"optional executable MCP tool names used to return one compact batch; mutually exclusive with tool_name, maximum 16"`
}
