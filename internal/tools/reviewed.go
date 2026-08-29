package tools

import (
	"fmt"
	"strconv"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func FFUFArgs(request dto.FFUFRequest) ([]string, error) {
	wordlist, err := resolveWordlist(request.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	args := []string{"ffuf", "-u", request.URL, "-w", wordlist, "-noninteractive", "-ac"}
	if request.FilterSize != "" {
		args = append(args, "-fs", request.FilterSize)
	}
	if request.Recursion {
		args = append(args, "-recursion")
	}
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
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
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
}

func NucleiArgs(request dto.NucleiRequest) ([]string, error) {
	args := []string{"nuclei", "-u", request.Target}
	if !request.AllowUnsafe {
		args = append(args, "-etags", "dos,fuzz", "-no-interactsh")
	}
	if request.Severity != "" {
		args = append(args, "-severity", request.Severity)
	}
	if request.Tags != "" {
		args = append(args, "-tags", request.Tags)
	}
	for _, template := range request.Templates {
		args = append(args, "-t", template)
	}
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
}

func WhatWebArgs(request dto.WhatWebRequest) ([]string, error) {
	args := []string{"whatweb"}
	if request.Aggression > 0 {
		args = append(args, "--aggression", strconv.Itoa(request.Aggression))
	}
	args, err := appendSplitArgs(args, request.AdditionalArgs, "additional_args")
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
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
}

func DalfoxArgs(request dto.DalfoxRequest) ([]string, error) {
	args := []string{"dalfox", "scan", request.Target, "--format", "json", "--no-color"}
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
}

func BrowserArgs(request dto.BrowserRequest) ([]string, error) {
	args := []string{"browser-check", "--url", request.URL}
	if request.WaitMilliseconds > 0 {
		args = append(args, "--wait-ms", strconv.Itoa(request.WaitMilliseconds))
	}
	if request.IncludeDOM {
		args = append(args, "--include-dom")
	}
	return args, nil
}

func RetireArgs(request dto.RetireRequest) ([]string, error) {
	args := []string{"retire", "--path", request.Path, "--outputformat", "json", "--exitwith", "0"}
	return appendSplitArgs(args, request.AdditionalArgs, "additional_args")
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
