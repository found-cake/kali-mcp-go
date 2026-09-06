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
	if err := validateControlRanges(options); err != nil {
		return dto.ScanOptions{}, err
	}
	if err := validateSupportedControls(tool, options); err != nil {
		return dto.ScanOptions{}, err
	}
	limits := profileLimits(options.Profile)
	if supportsRuntimeControl(tool, dto.ScanControlRateLimit) && limits.RateLimit > 0 {
		if options.RateLimit == 0 {
			options.RateLimit = limits.RateLimit
		} else if options.RateLimit > limits.RateLimit {
			return dto.ScanOptions{}, fmt.Errorf("rate_limit exceeds profile maximum %d", limits.RateLimit)
		}
	}
	if supportsRuntimeControl(tool, dto.ScanControlConcurrency) && limits.Concurrency > 0 {
		if options.Concurrency == 0 {
			options.Concurrency = limits.Concurrency
		} else if options.Concurrency > limits.Concurrency {
			return dto.ScanOptions{}, fmt.Errorf("concurrency exceeds profile maximum %d", limits.Concurrency)
		}
	}
	if supportsRuntimeControl(tool, dto.ScanControlTimeoutRequestBudget) && limits.TimeoutRequestBudget > 0 {
		if options.TimeoutRequestBudget == 0 {
			options.TimeoutRequestBudget = limits.TimeoutRequestBudget
		} else if options.TimeoutRequestBudget > limits.TimeoutRequestBudget {
			return dto.ScanOptions{}, fmt.Errorf("timeout_request_budget exceeds profile maximum %d", limits.TimeoutRequestBudget)
		}
	}
	if supportsRuntimeControl(tool, dto.ScanControlMax5xx) && limits.Max5xxResponses > 0 {
		if options.Max5xxResponses == 0 {
			options.Max5xxResponses = limits.Max5xxResponses
		} else if options.Max5xxResponses > limits.Max5xxResponses {
			return dto.ScanOptions{}, fmt.Errorf("max_5xx_responses exceeds profile maximum %d", limits.Max5xxResponses)
		}
	}
	if options.TimeoutRequestBudget > 0 && options.RateLimit == 0 {
		return dto.ScanOptions{}, fmt.Errorf("timeout_request_budget requires rate_limit")
	}
	return options, nil
}

func validateControlRanges(options dto.ScanOptions) error {
	if options.RateLimit < 0 || options.RateLimit > ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlRateLimit) {
		return fmt.Errorf("rate_limit must be between 1 and %d", ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlRateLimit))
	}
	if options.Concurrency < 0 || options.Concurrency > ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlConcurrency) {
		return fmt.Errorf("concurrency must be between 1 and %d", ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlConcurrency))
	}
	if options.TimeoutRequestBudget < 0 || options.TimeoutRequestBudget > ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlTimeoutRequestBudget) {
		return fmt.Errorf("timeout_request_budget must be between 1 and %d", ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlTimeoutRequestBudget))
	}
	if options.Max5xxResponses < 0 || options.Max5xxResponses > ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlMax5xx) {
		return fmt.Errorf("max_5xx_responses must be between 1 and %d", ScanControlMaximum(dto.ProfileExplicitCustom, dto.ScanControlMax5xx))
	}
	return nil
}

func validateSupportedControls(tool string, options dto.ScanOptions) error {
	requested := []struct {
		control dto.ScanControl
		value   int
	}{
		{dto.ScanControlRateLimit, options.RateLimit},
		{dto.ScanControlConcurrency, options.Concurrency},
		{dto.ScanControlTimeoutRequestBudget, options.TimeoutRequestBudget},
		{dto.ScanControlMax5xx, options.Max5xxResponses},
	}
	for _, request := range requested {
		if request.value > 0 && !supportsRuntimeControl(tool, request.control) {
			return fmt.Errorf("%s is not supported by %s", request.control, tool)
		}
	}
	return nil
}

func supportsRuntimeControl(tool string, control dto.ScanControl) bool {
	for _, capability := range scanToolCapabilities {
		if capability.RuntimeTool != tool {
			continue
		}
		for _, supported := range capability.Controls {
			if supported.Control == control {
				return true
			}
		}
	}
	return false
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
		case "dalfox":
			result = append(result, "--rate-limit", rate)
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
		case "hydra":
			result = replaceFlagValue(result, "-t", concurrency)
		}
	}
	return result, nil
}

func replaceFlagValue(args []string, flag, value string) []string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == flag {
			args[index+1] = value
			return args
		}
	}
	return append(args, flag, value)
}

func ScanControlApplication(tool string, requested, effective dto.ScanOptions) dto.ScanControlApplication {
	application := dto.ScanControlApplication{
		RequestedRateLimit: requested.RateLimit, RequestedConcurrency: requested.Concurrency,
	}
	for _, capability := range scanToolCapabilities {
		if capability.RuntimeTool != tool {
			continue
		}
		if supportsCapabilityControl(capability, dto.ScanControlRateLimit) {
			application.AppliedRateLimit = effective.RateLimit
		}
		if supportsCapabilityControl(capability, dto.ScanControlConcurrency) {
			application.AppliedConcurrency = effective.Concurrency
		}
		for _, control := range capability.Controls {
			if control.Control == dto.ScanControlTimeout || control.Control == dto.ScanControlDryRun {
				continue
			}
			requestedValue, effectiveValue := controlValues(control.Control, requested, effective)
			application.Controls = append(application.Controls, dto.AppliedScanControl{
				Control: control.Control, Requested: requestedValue, Effective: effectiveValue,
				Applied: effectiveValue > 0, Enforcement: control.Enforcement,
			})
		}
		break
	}
	return application
}

func supportsCapabilityControl(capability dto.ScanToolCapability, control dto.ScanControl) bool {
	for _, supported := range capability.Controls {
		if supported.Control == control {
			return true
		}
	}
	return false
}

func controlValues(control dto.ScanControl, requested, effective dto.ScanOptions) (int, int) {
	switch control {
	case dto.ScanControlRateLimit:
		return requested.RateLimit, effective.RateLimit
	case dto.ScanControlConcurrency:
		return requested.Concurrency, effective.Concurrency
	case dto.ScanControlTimeoutRequestBudget:
		return requested.TimeoutRequestBudget, effective.TimeoutRequestBudget
	case dto.ScanControlMax5xx:
		return requested.Max5xxResponses, effective.Max5xxResponses
	default:
		return 0, 0
	}
}

func profileLimits(profile dto.SafetyProfile) dto.ScanOptions {
	switch profile {
	case dto.ProfileSafeRecon:
		return dto.ScanOptions{RateLimit: 10, Concurrency: 2, TimeoutRequestBudget: 2000, Max5xxResponses: 20}
	case dto.ProfileWebDiscoveryLowRate:
		return dto.ScanOptions{RateLimit: 5, Concurrency: 2, TimeoutRequestBudget: 1000, Max5xxResponses: 10}
	case dto.ProfileSQLILowRisk:
		return dto.ScanOptions{RateLimit: 2, Concurrency: 1, TimeoutRequestBudget: 500, Max5xxResponses: 5}
	case dto.ProfileBrowserXSSConfirm:
		return dto.ScanOptions{RateLimit: 2, Concurrency: 1, TimeoutRequestBudget: 200, Max5xxResponses: 5}
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
