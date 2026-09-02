package tools

import (
	"os"
	"slices"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

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

func ScanCapabilities(availability ...func(string) bool) dto.ScanCapabilitiesResult {
	tools := make([]dto.ScanToolCapability, 0, len(scanToolCapabilities))
	for _, capability := range scanToolCapabilities {
		copy := cloneToolCapability(capability)
		copy.Profiles = append(copy.Profiles, dto.ProfileExplicitCustom)
		copy.SupportedControls = make([]dto.ScanControl, 0, len(copy.Controls))
		for _, control := range copy.Controls {
			copy.SupportedControls = append(copy.SupportedControls, control.Control)
		}
		if len(availability) > 0 && availability[0] != nil {
			copy.AvailabilityChecked = true
			copy.Available = copy.BuiltIn || availability[0](copy.RuntimeTool)
		}
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

func cloneToolCapability(capability dto.ScanToolCapability) dto.ScanToolCapability {
	copy := capability
	copy.Profiles = slices.Clone(capability.Profiles)
	copy.Controls = slices.Clone(capability.Controls)
	copy.SupportedControls = slices.Clone(capability.SupportedControls)
	return copy
}

func RuntimeToolNames() []string {
	names := make([]string, 0, len(scanToolCapabilities))
	seen := make(map[string]bool)
	for _, capability := range scanToolCapabilities {
		if capability.BuiltIn || seen[capability.RuntimeTool] {
			continue
		}
		seen[capability.RuntimeTool] = true
		names = append(names, capability.RuntimeTool)
	}
	slices.Sort(names)
	return names
}

func EssentialRuntimeToolNames() []string {
	names := make([]string, 0)
	for _, capability := range scanToolCapabilities {
		if capability.Essential {
			names = append(names, capability.RuntimeTool)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
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
			name:    "directory-discovery-small",
			purpose: "bounded web path and content discovery",
			path:    SmallDirWordlistPath(),
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
