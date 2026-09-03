package tools

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func NmapArgs(r dto.NmapRequest) ([]string, error) {
	scanType := r.ScanType
	if scanType == "" {
		scanType = "-sCV"
	}
	scanParts, err := splitArgs(scanType)
	if err != nil {
		return nil, fmt.Errorf("invalid scan_type: %w", err)
	}
	if err := rejectTargetSourceArgs(scanParts, "scan_type", true, "-iL", "-iR"); err != nil {
		return nil, err
	}
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-T4 -Pn"
	}
	args := append([]string{"nmap"}, scanParts...)
	if r.Ports != "" {
		args = append(args, "-p", r.Ports)
	}
	args, err = appendTargetSafeArgs(args, extra, "additional_args", true, "-iL", "-iR")
	if err != nil {
		return nil, err
	}
	return append(args, r.Target), nil
}

func TsharkArgs(r dto.TsharkRequest) ([]string, error) {
	readFile := strings.TrimSpace(r.ReadFile)
	iface := strings.TrimSpace(r.Interface)
	switch {
	case readFile == "" && iface == "":
		return nil, fmt.Errorf("read_file or interface is required")
	case readFile != "" && iface != "":
		return nil, fmt.Errorf("read_file and interface cannot be used together")
	}
	args := []string{"tshark"}
	if readFile != "" {
		args = append(args, "-r", readFile)
	} else {
		args = append(args, "-i", iface)
	}
	if r.CaptureFilter != "" {
		args = append(args, "-f", r.CaptureFilter)
	}
	if r.DisplayFilter != "" {
		args = append(args, "-Y", r.DisplayFilter)
	}
	if r.PacketCount != "" {
		args = append(args, "-c", r.PacketCount)
	}
	if r.Duration != "" {
		args = append(args, "-a", "duration:"+r.Duration)
	}
	if r.OutputFields != "" {
		args = append(args, "-T", "fields")
		for field := range strings.SplitSeq(r.OutputFields, ",") {
			if trimmed := strings.TrimSpace(field); trimmed != "" {
				args = append(args, "-e", trimmed)
			}
		}
	}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func Enum4linuxArgs(r dto.Enum4linuxRequest) ([]string, error) {
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-a"
	}
	args, err := appendTargetSafeArgs([]string{"enum4linux"}, extra, "additional_args", true)
	if err != nil {
		return nil, err
	}
	return append(args, r.Target), nil
}
