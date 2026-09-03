package tools

import "github.com/found-cake/kali-mcp-go/pkg/dto"

const mcpSchemaSource = "mcp_tools_list"

var scanToolCapabilities = []dto.ScanToolCapability{
	toolCapability("gobuster_scan", "gobuster", "/api/tools/gobuster/stream", "Discover web content, DNS subdomains, or virtual hosts with Gobuster. Directory mode automatically excludes stable SPA fallback response lengths.", dto.TargetInputURLOrHost, dto.ImpactActive, dto.ToolExecutionStream, true, []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, nativeControls(dto.ScanControlConcurrency)),
	toolCapability("metasploit_run", "msfconsole", "/api/tools/metasploit", "Run a specified Metasploit module against the authorized target.", dto.TargetInputModule, dto.ImpactExploit, dto.ToolExecutionPost, false, nil, nil),
	toolCapability("hydra_attack", "hydra", "/api/tools/hydra", "Run a short credential audit with Hydra. Use hydra_attack_stream for file-based or long-running attempts.", dto.TargetInputNetworkHost, dto.ImpactCredential, dto.ToolExecutionPost, false, nil, nativeControls(dto.ScanControlConcurrency)),
	toolCapability("john_crack", "john", "/api/tools/john", "Audit a supplied password hash with John the Ripper and optionally mask recovered plaintext.", dto.TargetInputOfflinePath, dto.ImpactCredential, dto.ToolExecutionPost, false, nil, nil),
	toolCapability("execute_command", "sh", "/api/command/stream", "Run a command in the Kali runtime when no dedicated MCP tool covers the authorized check.", dto.TargetInputCommand, dto.ImpactArbitraryExecution, dto.ToolExecutionStream, false, nil, nil),
	toolCapability("nmap_scan", "nmap", "/api/tools/nmap/stream", "Discover ports, services, and network exposure with Nmap.", dto.TargetInputNetworkHost, dto.ImpactActive, dto.ToolExecutionStream, true, []dto.SafetyProfile{dto.ProfileSafeRecon}, rateControls(false)),
	toolCapability("dirb_scan", "dirb", "/api/tools/dirb/stream", "Discover web paths and content with Dirb and a wordlist.", dto.TargetInputWebURL, dto.ImpactActive, dto.ToolExecutionStream, true, []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, nil),
	toolCapability("nikto_scan", "nikto", "/api/tools/nikto/stream", "Check a web server for common misconfigurations and known vulnerability patterns with Nikto.", dto.TargetInputURLOrHost, dto.ImpactActive, dto.ToolExecutionStream, true, []dto.SafetyProfile{dto.ProfileWebDiscoveryLowRate}, nil),
	toolCapability("sqlmap_scan", "sqlmap", "/api/tools/sqlmap/stream", "Verify a SQL-injection hypothesis from a URL, JSON body, or raw HTTP request with SQLmap.", dto.TargetInputURLOrFile, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileSQLILowRisk}, rateAndConcurrencyControls(false)),
	toolCapability("tshark_capture", "tshark", "/api/tools/tshark/stream", "Capture packets or analyze a PCAP with Tshark using explicit filters and limits.", dto.TargetInputCapture, dto.ImpactPassive, dto.ToolExecutionStream, true, nil, nil),
	toolCapability("hydra_attack_stream", "hydra", "/api/tools/hydra/stream", "Stream a long-running or file-based credential audit with Hydra.", dto.TargetInputNetworkHost, dto.ImpactCredential, dto.ToolExecutionStream, false, nil, nativeControls(dto.ScanControlConcurrency)),
	toolCapability("wpscan_analyze", "wpscan", "/api/tools/wpscan/stream", "Fingerprint and assess a WordPress target with WPScan.", dto.TargetInputWebURL, dto.ImpactActive, dto.ToolExecutionStream, false, nil, nil),
	toolCapability("enum4linux_scan", "enum4linux", "/api/tools/enum4linux/stream", "Enumerate Windows and Samba services with Enum4linux.", dto.TargetInputNetworkHost, dto.ImpactActive, dto.ToolExecutionStream, false, nil, nil),
	toolCapability("ffuf_scan", "ffuf", "/api/tools/ffuf/stream", "Discover web content with FFUF, including SPA fallback calibration, per-request timeouts, explicit status filtering, and recursion.", dto.TargetInputWebURL, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, rateAndConcurrencyControls(true)),
	toolCapability("feroxbuster_scan", "feroxbuster", "/api/tools/feroxbuster/stream", "Recursively discover web content with Feroxbuster and automatic SPA fallback calibration.", dto.TargetInputWebURL, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, rateAndConcurrencyControls(false)),
	toolCapability("nuclei_scan", "nuclei", "/api/tools/nuclei/stream", "Run template-based vulnerability checks with Nuclei. DoS, fuzz, and interactsh templates are excluded by default; dry_run previews the local template selection without contacting the target.", dto.TargetInputURLOrHost, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileSafeRecon}, append(rateAndConcurrencyControls(false), dto.ScanControlCapability{Control: dto.ScanControlDryRun, Enforcement: dto.ControlServerPreview})),
	toolCapability("whatweb_scan", "whatweb", "/api/tools/whatweb/stream", "Fingerprint web technologies and frameworks with WhatWeb, typically during initial reconnaissance.", dto.TargetInputURLOrHost, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, nil),
	toolCapability("jwt_analyze", "jwt_tool", "/api/tools/jwt/stream", "Parse JWT structure and metadata offline, with optional live endpoint verification for alg=none, forced-error, playbook, or key-confusion cases using jwt_tool.", dto.TargetInputToken, dto.ImpactActive, dto.ToolExecutionStream, false, nil, nil),
	toolCapability("dalfox_scan", "dalfox", "/api/tools/dalfox/stream", "Collect and verify reflected or server-routed XSS candidates with Dalfox; use browser_check for fragment-based DOM XSS.", dto.TargetInputURLOrFile, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileBrowserXSSConfirm}, nativeControls(dto.ScanControlConcurrency)),
	toolCapability("browser_check", "browser-check", "/api/tools/browser/stream", "Verify DOM-XSS execution at full SPA or hash-route URLs and inspect Chromium dialogs, console, network, screenshot, and rendered DOM evidence. The main-document navigation response is reported separately from the final SPA URL.", dto.TargetInputWebURL, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileBrowserXSSConfirm}, nil),
	toolCapability("retirejs_scan", "retire", "/api/tools/retire/stream", "Scan a page URL, a local bundle path, or explicit public JavaScript bundles copied from a browser_check network artifact via script_urls.", dto.TargetInputURLListOrFile, dto.ImpactActive, dto.ToolExecutionStream, false, []dto.SafetyProfile{dto.ProfileSafeRecon}, nil),
	toolCapability("osv_scan", "osv-scanner", "/api/tools/osv/stream", "Scan dependency manifests, lockfiles, or a source tree inside the Kali runtime with OSV-Scanner; use retirejs_scan when only public web bundles are available.", dto.TargetInputOfflinePath, dto.ImpactOffline, dto.ToolExecutionStream, false, nil, nil),
	toolCapability("http_request", "http-request", "/api/tools/http-request", "Send one bounded HTTP request to an explicitly selected target for manual validation and preserve raw request and response evidence unless redact_values is explicitly supplied.", dto.TargetInputWebURL, dto.ImpactActive, dto.ToolExecutionPost, false, []dto.SafetyProfile{dto.ProfileSafeRecon}, nil),
}

func toolCapability(name, runtime, endpoint, description string, target dto.TargetInputFormat, impact dto.ImpactLevel, mode dto.ToolExecutionMode, essential bool, profiles []dto.SafetyProfile, controls []dto.ScanControlCapability) dto.ScanToolCapability {
	requiresTargetContext := impact == dto.ImpactExploit || impact == dto.ImpactCredential && target == dto.TargetInputNetworkHost
	if requiresTargetContext {
		controls = append(controls, dto.ScanControlCapability{Control: dto.ScanControlDryRun, Enforcement: dto.ControlServerPreview})
	}
	return dto.ScanToolCapability{
		Tool: name, RuntimeTool: runtime, Endpoint: endpoint, Description: description,
		TargetInputFormat: target, ImpactLevel: impact, ExecutionMode: mode,
		InputSchemaSource: mcpSchemaSource, Essential: essential, BuiltIn: runtime == "http-request",
		RequiresTargetContext: requiresTargetContext,
		Profiles:              profiles,
		Controls: append([]dto.ScanControlCapability{{
			Control: dto.ScanControlTimeout, Enforcement: dto.ControlRequestTimeout,
		}}, controls...),
	}
}

func RuntimeRequiresTargetContext(runtimeTool string) bool {
	for _, capability := range scanToolCapabilities {
		if capability.RuntimeTool == runtimeTool && capability.RequiresTargetContext {
			return true
		}
	}
	return false
}

func nativeControls(controls ...dto.ScanControl) []dto.ScanControlCapability {
	result := make([]dto.ScanControlCapability, 0, len(controls))
	for _, control := range controls {
		result = append(result, dto.ScanControlCapability{Control: control, Enforcement: dto.ControlNativeCLI})
	}
	return result
}

func rateControls(observe5xx bool) []dto.ScanControlCapability {
	return appendBudgetControls(nativeControls(dto.ScanControlRateLimit), observe5xx)
}

func rateAndConcurrencyControls(observe5xx bool) []dto.ScanControlCapability {
	return appendBudgetControls(nativeControls(dto.ScanControlRateLimit, dto.ScanControlConcurrency), observe5xx)
}

func appendBudgetControls(controls []dto.ScanControlCapability, observe5xx bool) []dto.ScanControlCapability {
	controls = append(controls, dto.ScanControlCapability{Control: dto.ScanControlMaxRequests, Enforcement: dto.ControlDerivedTimeout})
	if observe5xx {
		controls = append(controls, dto.ScanControlCapability{Control: dto.ScanControlMax5xx, Enforcement: dto.ControlOutputObserver})
	}
	return controls
}

func ToolCapability(name string) (dto.ScanToolCapability, bool) {
	for _, capability := range scanToolCapabilities {
		if capability.Tool == name {
			return cloneToolCapability(capability), true
		}
	}
	return dto.ScanToolCapability{}, false
}
