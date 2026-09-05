package tools

import "github.com/found-cake/kali-mcp-go/pkg/dto"

func ScanControlMaximum(profile dto.SafetyProfile, control dto.ScanControl) int {
	if profile == "" || profile == dto.ProfileExplicitCustom {
		switch control {
		case dto.ScanControlRateLimit:
			return 1000
		case dto.ScanControlConcurrency:
			return 100
		case dto.ScanControlMaxRequests:
			return 1_000_000
		case dto.ScanControlMax5xx:
			return 1000
		default:
			return 0
		}
	}
	limits := profileLimits(profile)
	switch control {
	case dto.ScanControlRateLimit:
		return limits.RateLimit
	case dto.ScanControlConcurrency:
		return limits.Concurrency
	case dto.ScanControlMaxRequests:
		return limits.MaxRequests
	case dto.ScanControlMax5xx:
		return limits.Max5xxResponses
	default:
		return 0
	}
}
