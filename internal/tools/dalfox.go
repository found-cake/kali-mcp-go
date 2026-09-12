package tools

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func DalfoxArgs(request dto.DalfoxRequest) ([]string, error) {
	if err := rejectContextHostHeaders(request.ScanOptions, request.AdditionalArgs, "additional_args", "-H", "--headers"); err != nil {
		return nil, err
	}
	extra, err := splitArgs(request.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	if err := rejectDalfoxOverrides(request, extra); err != nil {
		return nil, err
	}

	args := []string{"dalfox", "scan", request.Target, "--format", "json", "--no-color"}
	headerNames := make([]string, 0, len(request.Headers))
	for name := range request.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		args = append(args, "--headers", name+": "+request.Headers[name])
	}
	if request.Cookies != "" {
		args = append(args, "--cookies", request.Cookies)
	}
	if request.RequestTimeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(request.RequestTimeout))
	}
	if request.ScanTimeout > 0 {
		args = append(args, "--scan-timeout", strconv.Itoa(request.ScanTimeout))
	}
	if request.Retries > 0 {
		args = append(args, "--retries", strconv.Itoa(request.Retries))
	}
	return append(args, extra...), nil
}

func rejectDalfoxOverrides(request dto.DalfoxRequest, extra []string) error {
	if err := rejectArguments(extra, "additional_args", "use the typed headers and cookies fields",
		"-H", "--header", "--headers", "--cookie", "--cookies", "--cookie-from-raw"); err != nil {
		return err
	}
	if err := rejectArguments(extra, "additional_args", "use the typed Dalfox request controls",
		"--rate-limit", "--timeout", "--scan-timeout", "--retries"); err != nil {
		return err
	}
	if err := rejectArguments(extra, "additional_args", "use concurrency", "--worker", "--workers"); err != nil {
		return err
	}
	if request.Profile == dto.ProfileBrowserXSSConfirm {
		if err := rejectArguments(extra, "additional_args", "browser-xss-confirm uses Dalfox's default GET request",
			"-X", "--method", "-d", "--data", "-F", "--follow-redirects", "-b", "--blind", "--blind-oob", "--blind-oob-secret",
			"--custom-blind-xss-payload", "--remote-payloads", "--remote-wordlists", "--proxy", "--sxss-url"); err != nil {
			return err
		}
	}
	if hasResolvedTarget(request.ScanOptions) {
		if err := rejectArguments(extra, "additional_args", "resolved targets forbid alternate outbound destinations",
			"-F", "--follow-redirects", "-b", "--blind", "--blind-oob", "--blind-oob-secret",
			"--custom-blind-xss-payload", "--remote-payloads", "--remote-wordlists", "--proxy", "--sxss-url"); err != nil {
			return err
		}
	}
	return rejectTargetSourceArgs(extra, "additional_args", true,
		"--file", "--rawdata", "--har-file", "--config", "--session-check-url")
}
