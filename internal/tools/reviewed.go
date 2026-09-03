package tools

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func FFUFArgs(request dto.FFUFRequest) ([]string, error) {
	wordlist, err := resolveWordlist(request.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	args := []string{"ffuf", "-u", request.URL, "-w", wordlist, "-noninteractive", "-ac", "-s", "-json"}
	if request.FilterSize != "" {
		args = append(args, "-fs", request.FilterSize)
	}
	if request.RequestTimeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(request.RequestTimeout))
	}
	if request.FilterStatuses != "" {
		args = append(args, "-fc", request.FilterStatuses)
	}
	if request.Recursion {
		args = append(args, "-recursion")
	}
	return appendTargetSafeArgs(args, request.AdditionalArgs, "additional_args", false, "-u", "-request", "-config")
}

func FeroxbusterArgs(request dto.FeroxbusterRequest) ([]string, error) {
	wordlist, err := resolveWordlist(request.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	args := []string{"feroxbuster", "--url", request.URL, "--wordlist", wordlist, "--auto-tune"}
	if request.FilterSize != "" {
		args = append(args, "--filter-size", request.FilterSize)
	}
	if request.Depth > 0 {
		args = append(args, "--depth", strconv.Itoa(request.Depth))
	}
	return appendTargetSafeArgs(args, request.AdditionalArgs, "additional_args", false, "--url", "--stdin", "--resume-from", "--request-file", "--config")
}

func NucleiArgs(request dto.NucleiRequest) ([]string, error) {
	additional, err := splitArgs(request.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	if err := rejectTargetSourceArgs(additional, "additional_args", false, "-u", "-target", "-l", "-list", "-resume"); err != nil {
		return nil, err
	}
	if err := validateNucleiSafety(request); err != nil {
		return nil, err
	}
	args := []string{"nuclei", "-u", request.Target, "-jsonl", "-disable-update-check"}
	if request.Severity != "" {
		args = append(args, "-severity", request.Severity)
	}
	if request.Tags != "" {
		args = append(args, "-tags", request.Tags)
	}
	for _, template := range request.Templates {
		args = append(args, "-t", template)
	}
	args = append(args, additional...)
	if !request.AllowUnsafe {
		args = append(args, "-etags", safeNucleiExcludedTags, "-no-interactsh")
	}
	return args, nil
}

func validateNucleiSafety(request dto.NucleiRequest) error {
	if request.AllowUnsafe {
		return nil
	}
	for _, selector := range append([]string{request.Tags}, request.Templates...) {
		lower := strings.ToLower(selector)
		if strings.Contains(lower, "dos") || strings.Contains(lower, "fuzz") || strings.Contains(lower, "dast") || strings.Contains(lower, "oast") || strings.Contains(lower, "interactsh") {
			return fmt.Errorf("unsafe Nuclei selector requires allow_unsafe")
		}
	}
	return validateSafeNucleiAdditionalArgs(request.AdditionalArgs)
}

func WhatWebArgs(request dto.WhatWebRequest) ([]string, error) {
	args := []string{"whatweb"}
	if request.Aggression > 0 {
		args = append(args, "--aggression", strconv.Itoa(request.Aggression))
	}
	args, err := appendTargetSafeArgs(args, request.AdditionalArgs, "additional_args", true, "-i", "--input-file")
	if err != nil {
		return nil, err
	}
	return append(args, request.Target), nil
}

func JWTToolArgs(request dto.JWTRequest) ([]string, error) {
	args := []string{"jwt_tool", request.Token}
	if request.TargetURL != "" {
		args = append(args, "-t", request.TargetURL)
	}
	if request.RequestHeader != "" {
		args = append(args, "-rh", request.RequestHeader)
	}
	if request.RequestCookie != "" {
		args = append(args, "-rc", request.RequestCookie)
	}
	if request.Canary != "" {
		args = append(args, "-cv", request.Canary)
	}
	mode := request.Mode
	if mode == "" && request.TargetURL != "" {
		mode = "at"
	}
	if err := validateJWTMode(mode); err != nil {
		return nil, err
	}
	if mode != "" {
		args = append(args, "-M", mode)
	}
	if request.PublicKey != "" {
		args = append(args, "-pk", request.PublicKey)
	}
	return appendTargetSafeArgs(args, request.AdditionalArgs, "additional_args", false, "-t")
}

func DalfoxArgs(request dto.DalfoxRequest) ([]string, error) {
	args := []string{"dalfox", "scan", request.Target, "--format", "json", "--no-color"}
	extra, err := splitArgs(request.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	for _, argument := range extra {
		if argument == "--worker" || argument == "--workers" || strings.HasPrefix(argument, "--worker=") || strings.HasPrefix(argument, "--workers=") {
			return nil, fmt.Errorf("additional_args must not set Dalfox worker flags; use concurrency")
		}
	}
	if err := rejectTargetSourceArgs(extra, "additional_args", false, "--file", "--rawdata", "--har-file"); err != nil {
		return nil, err
	}
	return append(args, extra...), nil
}

func BrowserArgs(request dto.BrowserRequest) ([]string, error) {
	args := []string{"browser-check", "--url", request.URL}
	if request.WaitMilliseconds > 0 {
		args = append(args, "--wait-ms", strconv.Itoa(request.WaitMilliseconds))
	}
	if request.IncludeDOM {
		args = append(args, "--include-dom")
	}
	if request.CaptureNetwork {
		args = append(args, "--capture-network")
	}
	if request.CaptureScreenshot {
		args = append(args, "--capture-screenshot")
	}
	return args, nil
}

func RetireArgs(request dto.RetireRequest) ([]string, error) {
	args := []string{"retire", "--path", request.Path, "--outputformat", "json", "--exitwith", "0"}
	return appendTargetSafeArgs(args, request.AdditionalArgs, "additional_args", false, "--path")
}

func OSVArgs(request dto.OSVRequest) ([]string, error) {
	args := []string{"osv-scanner", "scan", "source", "-r", request.Path, "--format", "json"}
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
}

func validateJWTMode(mode string) error {
	switch mode {
	case "", "pb", "er", "at":
		return nil
	default:
		return fmt.Errorf("mode must be pb|er|at")
	}
}
