package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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
	return nil
}

func validateNiktoRequest(req dto.NiktoRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

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
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}
