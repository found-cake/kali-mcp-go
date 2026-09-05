package toolapi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func containsLineBreak(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func validatePositiveInt(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fmt.Errorf("%s must be a positive integer", name)
	}
	return nil
}

func validateTsharkRequest(req dto.TsharkRequest) error {
	readFile := strings.TrimSpace(req.ReadFile)
	iface := strings.TrimSpace(req.Interface)
	switch {
	case readFile == "" && iface == "":
		return fmt.Errorf("read_file or interface is required")
	case readFile != "" && iface != "":
		return fmt.Errorf("read_file and interface cannot be used together")
	}
	if err := validatePositiveInt("packet_count", req.PacketCount); err != nil {
		return err
	}
	if err := validatePositiveInt("duration", req.Duration); err != nil {
		return err
	}
	if strings.TrimSpace(req.OutputFields) != "" && !hasNonEmptyCSVField(req.OutputFields) {
		return fmt.Errorf("output_fields must contain at least one field")
	}
	return nil
}

func hasNonEmptyCSVField(value string) bool {
	for field := range strings.SplitSeq(value, ",") {
		if strings.TrimSpace(field) != "" {
			return true
		}
	}
	return false
}

func commandTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return dto.DefaultTimeout
	}
	return time.Duration(seconds) * time.Second
}

func validateHydraRequest(req dto.HydraRequest) error {
	if req.Target == "" || req.Service == "" {
		return fmt.Errorf("target and service are required")
	}
	if req.Username != "" && req.UsernameFile != "" {
		return fmt.Errorf("username and username_file cannot be used together")
	}
	if req.Password != "" && req.PasswordFile != "" {
		return fmt.Errorf("password and password_file cannot be used together")
	}
	if req.Username == "" && req.UsernameFile == "" {
		return fmt.Errorf("username or username_file is required")
	}
	if req.Password == "" && req.PasswordFile == "" {
		return fmt.Errorf("password or password_file is required")
	}
	if req.Port < 0 || req.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, or 0 when unset")
	}
	return nil
}

func validateNiktoRequest(req dto.NiktoRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	if req.PauseSeconds < 0 {
		return fmt.Errorf("pause_seconds must not be negative")
	}
	if req.MaxTime != "" && !niktoMaxTime.MatchString(req.MaxTime) {
		return fmt.Errorf("max_time must be a positive duration such as 120s or 10m")
	}
	return nil
}

var niktoMaxTime = regexp.MustCompile(`^[1-9][0-9]*[smh]?$`)

func validateNmapRequest(req dto.NmapRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

func validateDirbRequest(req dto.DirbRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}

func validateWPScanRequest(req dto.WPScanRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}

func validateEnum4linuxRequest(req dto.Enum4linuxRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

func validateSQLMapRequest(req dto.SQLMapRequest) error {
	sources := 0
	for _, source := range []string{req.URL, req.RequestFile, req.RawRequest} {
		if strings.TrimSpace(source) != "" {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("provide exactly one of url, request_file, or raw_request")
	}
	for name, value := range req.Headers {
		if strings.TrimSpace(name) == "" || containsLineBreak(name) || containsLineBreak(value) {
			return fmt.Errorf("headers must have non-empty names and no line breaks")
		}
	}
	if containsLineBreak(req.Cookie) || containsLineBreak(req.ContentType) {
		return fmt.Errorf("cookie and content_type must not contain line breaks")
	}
	return nil
}

func validateGobusterRequest(req dto.GobusterRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	if !tools.ValidGobusterMode(req.Mode) {
		return fmt.Errorf("mode must be dir|dns|fuzz|vhost")
	}
	return nil
}

func validateJohnRequest(req dto.JohnRequest) error {
	if (req.Hash == "") == (req.HashFile == "") {
		return fmt.Errorf("provide exactly one of hash or hash_file")
	}
	return nil
}

func validateFFUFRequest(req dto.FFUFRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	if req.RequestTimeout < 0 || req.RequestTimeout > 300 {
		return fmt.Errorf("request_timeout must be between 1 and 300 seconds, or 0 for the FFUF default")
	}
	if req.FilterStatuses != "" {
		for item := range strings.SplitSeq(req.FilterStatuses, ",") {
			bounds := strings.Split(strings.TrimSpace(item), "-")
			if len(bounds) < 1 || len(bounds) > 2 {
				return fmt.Errorf("filter_status_codes must contain HTTP codes between 100 and 599")
			}
			lower, err := strconv.Atoi(bounds[0])
			if err != nil || lower < 100 || lower > 599 {
				return fmt.Errorf("filter_status_codes must contain HTTP codes between 100 and 599")
			}
			upper := lower
			if len(bounds) == 2 {
				upper, err = strconv.Atoi(bounds[1])
			}
			if err != nil || upper < lower || upper > 599 {
				return fmt.Errorf("filter_status_codes must contain HTTP codes between 100 and 599")
			}
		}
	}
	return nil
}

func validateFeroxbusterRequest(req dto.FeroxbusterRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	if req.Depth < 0 {
		return fmt.Errorf("depth must not be negative")
	}
	return nil
}

func validateNucleiRequest(req dto.NucleiRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	for _, template := range req.Templates {
		if strings.TrimSpace(template) == "" {
			return fmt.Errorf("templates must not contain empty values")
		}
	}
	return nil
}

func validateWhatWebRequest(req dto.WhatWebRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	if req.Aggression < 0 || req.Aggression > 4 {
		return fmt.Errorf("aggression must be between 1 and 4")
	}
	return nil
}

func validateJWTRequest(req dto.JWTRequest) error {
	if req.Token == "" {
		return fmt.Errorf("token is required")
	}
	switch req.Mode {
	case "", "pb", "er", "at":
	default:
		return fmt.Errorf("mode must be pb|er|at")
	}
	if req.TargetURL == "" {
		if req.RequestHeader != "" || req.RequestCookie != "" {
			return fmt.Errorf("target_url is required with request_header or request_cookie")
		}
		return nil
	}
	if (req.RequestHeader == "") == (req.RequestCookie == "") {
		return fmt.Errorf("exactly one of request_header or request_cookie is required for a live target")
	}
	template := req.RequestHeader
	if template == "" {
		template = req.RequestCookie
	}
	if strings.Count(template, "JWT_HERE") != 1 {
		return fmt.Errorf("live request template must contain JWT_HERE exactly once")
	}
	return nil
}

func validateDalfoxRequest(req dto.DalfoxRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

const maxBrowserWaitMilliseconds = 30_000

func validateBrowserRequest(req dto.BrowserRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	if req.WaitMilliseconds < 0 || req.WaitMilliseconds > maxBrowserWaitMilliseconds {
		return fmt.Errorf("wait_milliseconds must be between 0 and %d", maxBrowserWaitMilliseconds)
	}
	return nil
}

func validateOSVRequest(req dto.OSVRequest) error {
	if req.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}
