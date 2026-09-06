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
	if err := validateOptionalBoundedInt("request_timeout", req.RequestTimeout, 300); err != nil {
		return err
	}
	if err := validateOptionalBoundedInt("failure_limit", req.FailureLimit, 1000); err != nil {
		return err
	}
	return nil
}

var niktoMaxTime = regexp.MustCompile(`^[1-9][0-9]*[smh]?$`)

func validateNmapRequest(req dto.NmapRequest) error {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/ 	\r\n") {
		return fmt.Errorf("target must be a single IP address or hostname, not a URL or target list")
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
	if req.Profile == dto.ProfileSafeRecon && !req.DryRun && strings.TrimSpace(req.Severity) == "" && strings.TrimSpace(req.Tags) == "" && len(req.Templates) == 0 {
		return fmt.Errorf("safe-recon execution requires severity, tags, or templates; use dry_run to preview all safe templates")
	}
	for _, template := range req.Templates {
		if strings.TrimSpace(template) == "" {
			return fmt.Errorf("templates must not contain empty values")
		}
	}
	if err := validateOptionalBoundedInt("max_host_errors", req.MaxHostErrors, 1000); err != nil {
		return err
	}
	if err := validateOptionalBoundedInt("request_timeout", req.RequestTimeout, 300); err != nil {
		return err
	}
	if err := validateOptionalBoundedInt("retries", req.Retries, 10); err != nil {
		return err
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

func validateDalfoxRequest(req dto.DalfoxRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	if err := validateOptionalBoundedInt("request_timeout", req.RequestTimeout, 300); err != nil {
		return err
	}
	if err := validateOptionalBoundedInt("scan_timeout", req.ScanTimeout, 3600); err != nil {
		return err
	}
	if err := validateOptionalBoundedInt("retries", req.Retries, 10); err != nil {
		return err
	}
	return nil
}

func validateOptionalBoundedInt(name string, value, maximum int) error {
	if value < 0 || value > maximum {
		return fmt.Errorf("%s must be between 1 and %d, or 0 when unset", name, maximum)
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
	return validateAuthenticatedHeaders(req.Headers)
}

func validateOSVRequest(req dto.OSVRequest) error {
	if req.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}
