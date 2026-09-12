package tools

import "github.com/found-cake/kali-mcp-go/pkg/dto"

func isDiscoveryProfile(profile dto.SafetyProfile) bool {
	return profile == dto.ProfileSafeRecon || profile == dto.ProfileWebDiscoveryLowRate
}

func hasResolvedTarget(options dto.ScanOptions) bool {
	return options.TargetContext != "" || options.ResolutionReceipt != ""
}
