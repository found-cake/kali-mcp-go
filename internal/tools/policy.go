package tools

import (
	"fmt"
	"strconv"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func EffectiveScanOptions(tool string, options dto.ScanOptions) (dto.ScanOptions, error) {
	if err := ValidateScanProfile(tool, options); err != nil {
		return dto.ScanOptions{}, err
	}
	limits := profileLimits(options.Profile)
	if limits.RateLimit > 0 {
		if options.RateLimit == 0 {
			options.RateLimit = limits.RateLimit
		} else if options.RateLimit > limits.RateLimit {
			return dto.ScanOptions{}, fmt.Errorf("rate_limit exceeds profile maximum %d", limits.RateLimit)
		}
	}
	if limits.Concurrency > 0 {
		if options.Concurrency == 0 {
			options.Concurrency = limits.Concurrency
		} else if options.Concurrency > limits.Concurrency {
			return dto.ScanOptions{}, fmt.Errorf("concurrency exceeds profile maximum %d", limits.Concurrency)
		}
	}
	if limits.MaxRequests > 0 {
		if options.MaxRequests == 0 {
			options.MaxRequests = limits.MaxRequests
		} else if options.MaxRequests > limits.MaxRequests {
			return dto.ScanOptions{}, fmt.Errorf("max_requests exceeds profile maximum %d", limits.MaxRequests)
		}
	}
	if options.MaxRequests > 0 && options.RateLimit == 0 {
		return dto.ScanOptions{}, fmt.Errorf("max_requests requires rate_limit for enforceable budgeting")
	}
	if options.RateLimit < 0 || options.RateLimit > 1000 {
		return dto.ScanOptions{}, fmt.Errorf("rate_limit must be between 1 and 1000")
	}
	if options.Concurrency < 0 || options.Concurrency > 100 {
		return dto.ScanOptions{}, fmt.Errorf("concurrency must be between 1 and 100")
	}
	if options.MaxRequests < 0 || options.MaxRequests > 1000000 {
		return dto.ScanOptions{}, fmt.Errorf("max_requests must be between 1 and 1000000")
	}
	if options.Max5xxResponses < 0 || options.Max5xxResponses > 1000 {
		return dto.ScanOptions{}, fmt.Errorf("max_5xx_responses must be between 1 and 1000")
	}
	return options, nil
}

func ValidateScanProfile(tool string, options dto.ScanOptions) error {
	if options.Profile == "" || options.Profile == dto.ProfileExplicitCustom {
		return nil
	}
	allowed := profileTools(options.Profile)
	if allowed == nil {
		return fmt.Errorf("unknown scan profile %q", options.Profile)
	}
	if !allowed[tool] {
		return fmt.Errorf("profile %q does not allow %s", options.Profile, tool)
	}
	return nil
}

func ApplyScanControls(args []string, options dto.ScanOptions) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("scan command is empty")
	}
	result := append([]string(nil), args...)
	if options.RateLimit > 0 {
		rate := strconv.Itoa(options.RateLimit)
		switch args[0] {
		case "nuclei":
			result = append(result, "-rl", rate)
		case "ffuf":
			result = append(result, "-rate", rate)
		case "feroxbuster":
			result = append(result, "--rate-limit", rate)
		case "nmap":
			result = append(result, "--max-rate", rate)
		case "sqlmap":
			result = append(result, "--delay", strconv.FormatFloat(1/float64(options.RateLimit), 'f', 3, 64))
		}
	}
	if options.Concurrency > 0 {
		concurrency := strconv.Itoa(options.Concurrency)
		switch args[0] {
		case "nuclei":
			result = append(result, "-c", concurrency)
		case "ffuf":
			result = append(result, "-t", concurrency)
		case "feroxbuster":
			result = append(result, "--threads", concurrency)
		case "gobuster":
			result = append(result, "--threads", concurrency)
		case "sqlmap":
			result = append(result, "--threads", concurrency)
		case "dalfox":
			result = append(result, "--workers", concurrency)
		}
	}
	return result, nil
}

func profileLimits(profile dto.SafetyProfile) dto.ScanOptions {
	switch profile {
	case dto.ProfileSafeRecon:
		return dto.ScanOptions{RateLimit: 10, Concurrency: 2, MaxRequests: 2000, Max5xxResponses: 20}
	case dto.ProfileWebDiscoveryLowRate:
		return dto.ScanOptions{RateLimit: 5, Concurrency: 2, MaxRequests: 1000, Max5xxResponses: 10}
	case dto.ProfileSQLILowRisk:
		return dto.ScanOptions{RateLimit: 2, Concurrency: 1, MaxRequests: 500, Max5xxResponses: 5}
	case dto.ProfileBrowserXSSConfirm:
		return dto.ScanOptions{RateLimit: 2, Concurrency: 1, MaxRequests: 200, Max5xxResponses: 5}
	default:
		return dto.ScanOptions{}
	}
}

func profileTools(profile dto.SafetyProfile) map[string]bool {
	switch profile {
	case dto.ProfileSafeRecon, dto.ProfileWebDiscoveryLowRate, dto.ProfileSQLILowRisk, dto.ProfileBrowserXSSConfirm:
		return compatibleRuntimeTools(profile)
	default:
		return nil
	}
}
