package targeting

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func ApplyContext[T any](secret string, request T, now time.Time) (T, error) {
	scanRequest, ok := any(request).(dto.ScanRequest)
	if !ok {
		return request, nil
	}
	options := scanRequest.GetScanOptions()
	if options.TargetContext == "" {
		return request, nil
	}
	if options.ResolutionReceipt != "" {
		return request, fmt.Errorf("target_context and resolution_receipt cannot be used together")
	}
	claims, err := verifyTargetContext(secret, options.TargetContext, now)
	if err != nil {
		return request, err
	}
	if err := applyContextTarget(&request, claims); err != nil {
		return request, err
	}
	return request, nil
}

func applyContextTarget(request any, claims targetContextClaims) error {
	switch value := request.(type) {
	case *dto.MetasploitRequest:
		if err := setNetworkTarget(&value.Target, claims.NetworkTarget); err != nil {
			return err
		}
		return bindMetasploitPort(value, claims.Port)
	case *dto.NmapRequest:
		if err := setNetworkTarget(&value.Target, claims.NetworkTarget); err != nil {
			return err
		}
		return bindStringPort(&value.Ports, claims.Port, "Nmap")
	case *dto.GobusterRequest:
		if strings.EqualFold(value.Mode, "dns") {
			return setNetworkTarget(&value.URL, claims.NetworkTarget)
		}
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.DirbRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.NiktoRequest:
		return setWebTarget(&value.Target, claims.BrowserTarget)
	case *dto.SQLMapRequest:
		if err := rejectExplicitHostHeader(value.Headers); err != nil {
			return err
		}
		if value.RequestFile != "" || value.RawRequest != "" {
			return nil
		}
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.HydraRequest:
		if err := setNetworkTarget(&value.Target, claims.NetworkTarget); err != nil {
			return err
		}
		return bindIntPort(&value.Port, claims.Port, "Hydra")
	case *dto.WPScanRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.Enum4linuxRequest:
		return setNetworkTarget(&value.Target, claims.NetworkTarget)
	case *dto.FFUFRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.FeroxbusterRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.NucleiRequest:
		return setURLOrHostTarget(&value.Target, claims)
	case *dto.WhatWebRequest:
		return setURLOrHostTarget(&value.Target, claims)
	case *dto.JWTRequest:
		if err := rejectHostHeaderText(value.RequestHeader); err != nil {
			return err
		}
		return setWebTarget(&value.TargetURL, claims.BrowserTarget)
	case *dto.DalfoxRequest:
		return setWebTarget(&value.Target, claims.BrowserTarget)
	case *dto.BrowserRequest:
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.RetireRequest:
		if len(value.ScriptURLs) > 0 {
			for index := range value.ScriptURLs {
				if err := setWebTarget(&value.ScriptURLs[index], claims.BrowserTarget); err != nil {
					return fmt.Errorf("script_urls[%d]: %w", index, err)
				}
			}
			return nil
		}
		return setWebTarget(&value.URL, claims.BrowserTarget)
	case *dto.HTTPRequest:
		if err := rejectExplicitHostHeader(value.Headers); err != nil {
			return err
		}
		return setWebTarget(&value.URL, claims.BrowserTarget)
	default:
		return fmt.Errorf("target_context is not supported for this request")
	}
}

func bindStringPort(current *string, expected int, tool string) error {
	if expected == 0 {
		return nil
	}
	want := strconv.Itoa(expected)
	if strings.TrimSpace(*current) != "" && strings.TrimSpace(*current) != want {
		return fmt.Errorf("%s port does not match target_context port %d", tool, expected)
	}
	*current = want
	return nil
}

func bindIntPort(current *int, expected int, tool string) error {
	if expected == 0 {
		return nil
	}
	if *current != 0 && *current != expected {
		return fmt.Errorf("%s port does not match target_context port %d", tool, expected)
	}
	*current = expected
	return nil
}

func bindMetasploitPort(request *dto.MetasploitRequest, expected int) error {
	if expected == 0 {
		return nil
	}
	options := make(map[string]string, len(request.Options)+1)
	for name, value := range request.Options {
		if strings.EqualFold(strings.TrimSpace(name), "RPORT") {
			port, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || port != expected {
				return fmt.Errorf("Metasploit RPORT does not match target_context port %d", expected)
			}
			continue
		}
		options[name] = value
	}
	options["RPORT"] = strconv.Itoa(expected)
	request.Options = options
	return nil
}

func rejectExplicitHostHeader(headers map[string]string) error {
	for name := range headers {
		if strings.EqualFold(strings.TrimSpace(name), "Host") {
			return fmt.Errorf("Host header overrides are not permitted with target_context")
		}
	}
	return nil
}

func rejectHostHeaderText(value string) error {
	for line := range strings.Lines(strings.ReplaceAll(value, "\r\n", "\n")) {
		name, _, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "Host") {
			return fmt.Errorf("Host header overrides are not permitted with target_context")
		}
	}
	return nil
}

func setNetworkTarget(current *string, expected string) error {
	if *current != "" && !strings.EqualFold(*current, expected) {
		return fmt.Errorf("request target does not match target_context network target")
	}
	*current = expected
	return nil
}

func setWebTarget(current *string, expected string) error {
	if expected == "" {
		return fmt.Errorf("target_context does not contain a browser target")
	}
	if *current != "" {
		currentOrigin, currentOK := Origin(*current)
		expectedOrigin, expectedOK := Origin(expected)
		if !currentOK || !expectedOK || currentOrigin != expectedOrigin {
			return fmt.Errorf("request URL does not match target_context browser origin; use the selected candidate browser_target %s or omit the request URL", expected)
		}
		return nil
	}
	*current = expected
	return nil
}

func setURLOrHostTarget(current *string, claims targetContextClaims) error {
	if *current != "" && !strings.Contains(*current, "://") {
		if claims.BrowserTarget != "" && claims.Port > 0 {
			if !strings.EqualFold(strings.Trim(strings.TrimSpace(*current), "[]"), strings.Trim(strings.TrimSpace(claims.NetworkTarget), "[]")) {
				return fmt.Errorf("request target does not match target_context network target")
			}
			*current = claims.BrowserTarget
			return nil
		}
		return setNetworkTarget(current, claims.NetworkTarget)
	}
	if claims.BrowserTarget != "" {
		return setWebTarget(current, claims.BrowserTarget)
	}
	return setNetworkTarget(current, claims.NetworkTarget)
}
