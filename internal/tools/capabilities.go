package tools

import (
	"os"
	"slices"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

var scanToolCapabilities = []dto.ScanToolCapability{
	{Tool: "nmap_scan", RuntimeTool: "nmap", TargetInputFormat: dto.TargetInputNetworkHost, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon}, SupportedControls: []dto.ScanControl{dto.ScanControlRateLimit}},
	{Tool: "gobuster_scan", RuntimeTool: "gobuster", TargetInputFormat: dto.TargetInputURLOrHost, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, SupportedControls: []dto.ScanControl{dto.ScanControlConcurrency}},
	{Tool: "dirb_scan", RuntimeTool: "dirb", TargetInputFormat: dto.TargetInputWebURL, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}},
	{Tool: "nikto_scan", RuntimeTool: "nikto", TargetInputFormat: dto.TargetInputURLOrHost, Profiles: []dto.SafetyProfile{dto.ProfileWebDiscoveryLowRate}},
	{Tool: "sqlmap_scan", RuntimeTool: "sqlmap", TargetInputFormat: dto.TargetInputURLOrFile, Profiles: []dto.SafetyProfile{dto.ProfileSQLILowRisk}, SupportedControls: []dto.ScanControl{dto.ScanControlRateLimit, dto.ScanControlConcurrency}},
	{Tool: "hydra_attack", RuntimeTool: "hydra", TargetInputFormat: dto.TargetInputNetworkHost},
	{Tool: "wpscan_analyze", RuntimeTool: "wpscan", TargetInputFormat: dto.TargetInputWebURL},
	{Tool: "enum4linux_scan", RuntimeTool: "enum4linux", TargetInputFormat: dto.TargetInputNetworkHost},
	{Tool: "ffuf_scan", RuntimeTool: "ffuf", TargetInputFormat: dto.TargetInputWebURL, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, SupportedControls: []dto.ScanControl{dto.ScanControlRateLimit, dto.ScanControlConcurrency}},
	{Tool: "feroxbuster_scan", RuntimeTool: "feroxbuster", TargetInputFormat: dto.TargetInputWebURL, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}, SupportedControls: []dto.ScanControl{dto.ScanControlRateLimit, dto.ScanControlConcurrency}},
	{Tool: "nuclei_scan", RuntimeTool: "nuclei", TargetInputFormat: dto.TargetInputURLOrHost, SupportedControls: []dto.ScanControl{dto.ScanControlRateLimit, dto.ScanControlConcurrency}},
	{Tool: "whatweb_scan", RuntimeTool: "whatweb", TargetInputFormat: dto.TargetInputURLOrHost, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate}},
	{Tool: "jwt_analyze", RuntimeTool: "jwt_tool", TargetInputFormat: dto.TargetInputToken},
	{Tool: "dalfox_scan", RuntimeTool: "dalfox", TargetInputFormat: dto.TargetInputURLOrFile, Profiles: []dto.SafetyProfile{dto.ProfileBrowserXSSConfirm}, SupportedControls: []dto.ScanControl{dto.ScanControlConcurrency}},
	{Tool: "browser_check", RuntimeTool: "browser-check", TargetInputFormat: dto.TargetInputWebURL, Profiles: []dto.SafetyProfile{dto.ProfileBrowserXSSConfirm}},
	{Tool: "retirejs_scan", RuntimeTool: "retire", TargetInputFormat: dto.TargetInputURLOrFile},
	{Tool: "http_request", RuntimeTool: "http-request", TargetInputFormat: dto.TargetInputWebURL, Profiles: []dto.SafetyProfile{dto.ProfileSafeRecon}},
}

var orderedProfiles = []dto.SafetyProfile{
	dto.ProfileSafeRecon,
	dto.ProfileWebDiscoveryLowRate,
	dto.ProfileSQLILowRisk,
	dto.ProfileBrowserXSSConfirm,
	dto.ProfileExplicitCustom,
}

type wordlistDefinition struct {
	name       string
	purpose    string
	path       string
	defaultFor []string
}

func ScanCapabilities() dto.ScanCapabilitiesResult {
	tools := make([]dto.ScanToolCapability, 0, len(scanToolCapabilities))
	for _, capability := range scanToolCapabilities {
		copy := capability
		copy.Profiles = append(slices.Clone(capability.Profiles), dto.ProfileExplicitCustom)
		copy.SupportedControls = slices.Clone(capability.SupportedControls)
		tools = append(tools, copy)
	}

	profiles := make([]dto.ScanProfileCapability, 0, len(orderedProfiles))
	for _, profile := range orderedProfiles {
		limits := profileLimits(profile)
		profiles = append(profiles, dto.ScanProfileCapability{
			Profile: profile,
			Tools:   compatibleMCPTools(profile),
			Limits: dto.ScanLimits{
				MaxRequests:     limits.MaxRequests,
				RateLimit:       limits.RateLimit,
				Concurrency:     limits.Concurrency,
				Max5xxResponses: limits.Max5xxResponses,
			},
		})
	}
	return dto.ScanCapabilitiesResult{Profiles: profiles, Tools: tools, Wordlists: wordlistCapabilities()}
}

func wordlistCapabilities() []dto.WordlistCapability {
	return []dto.WordlistCapability{
		wordlistCapability(wordlistDefinition{
			name:       "directory-discovery",
			purpose:    "web path and content discovery",
			path:       DefaultDirWordlistPath(),
			defaultFor: []string{"gobuster_scan", "dirb_scan", "ffuf_scan", "feroxbuster_scan"},
		}),
		wordlistCapability(wordlistDefinition{
			name:       "password-audit",
			purpose:    "password hash auditing",
			path:       DefaultJohnWordlistPath(),
			defaultFor: []string{"john_crack"},
		}),
	}
}

func wordlistCapability(definition wordlistDefinition) dto.WordlistCapability {
	capability := dto.WordlistCapability{
		Name:       definition.name,
		Path:       definition.path,
		Purpose:    definition.purpose,
		DefaultFor: slices.Clone(definition.defaultFor),
	}
	info, err := os.Stat(definition.path)
	if err == nil && info.Mode().IsRegular() {
		capability.Available = true
		capability.SizeBytes = info.Size()
	}
	return capability
}

func compatibleMCPTools(profile dto.SafetyProfile) []string {
	tools := make([]string, 0, len(scanToolCapabilities))
	for _, capability := range scanToolCapabilities {
		if profile == dto.ProfileExplicitCustom || slices.Contains(capability.Profiles, profile) {
			tools = append(tools, capability.Tool)
		}
	}
	return tools
}

func compatibleRuntimeTools(profile dto.SafetyProfile) map[string]bool {
	tools := make(map[string]bool)
	for _, capability := range scanToolCapabilities {
		if slices.Contains(capability.Profiles, profile) {
			tools[capability.RuntimeTool] = true
		}
	}
	return tools
}
