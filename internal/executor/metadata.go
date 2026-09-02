package executor

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var versionCache sync.Map

func toolVersion(ctx context.Context, name string) string {
	if cached, ok := versionCache.Load(name); ok {
		if version, valid := cached.(string); valid {
			return version
		}
	}
	versionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(versionCtx, name, versionArguments(name)...).CombinedOutput()
	version := "unknown"
	if err == nil {
		version = versionLine(name, string(output))
	}
	versionCache.Store(name, version)
	return version
}

func versionArguments(name string) []string {
	switch name {
	case "ffuf":
		return []string{"-V"}
	case "nuclei":
		return []string{"-version"}
	case "enum4linux":
		return []string{"-h"}
	case "nikto":
		return []string{"-Version"}
	case "john":
		return []string{"--list=build-info"}
	default:
		return []string{"--version"}
	}
}

func commandTool(name string, args []string) string {
	if name != "env" {
		return name
	}
	for _, arg := range args {
		if arg == "john" {
			return arg
		}
	}
	return name
}

func versionLine(name, output string) string {
	fallback := "unknown"
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if fallback == "unknown" {
			fallback = line
		}
		switch name {
		case "john":
			if strings.HasPrefix(line, "Version:") {
				return line
			}
		case "tshark":
			if strings.HasPrefix(line, "TShark (Wireshark)") {
				return line
			}
		case "wpscan":
			if strings.HasPrefix(line, "Current Version:") {
				return line
			}
		}
	}
	return fallback
}

func redactArgs(name string, args []string) []string {
	redacted := append([]string(nil), args...)
	for index := range redacted {
		if index > 0 && name == "browser-check" && redacted[index-1] == "--screenshot-path" {
			redacted[index] = "[EPHEMERAL_FILE]"
			continue
		}
		if index > 0 && sensitiveFlag(name, redacted[index-1]) {
			redacted[index] = "[REDACTED]"
			continue
		}
		lower := strings.ToLower(redacted[index])
		if strings.HasPrefix(lower, "authorization:") || strings.HasPrefix(lower, "cookie:") {
			redacted[index] = "[REDACTED]"
		}
	}
	if name == "jwt_tool" && len(redacted) > 0 {
		redacted[0] = "[REDACTED]"
	}
	return redacted
}

func sensitiveFlag(name, flag string) bool {
	switch flag {
	case "--cookie", "--header", "-H", "-rh", "-rc":
		return true
	case "-b", "-c":
		return name == "ffuf" || name == "gobuster" || name == "nuclei"
	case "-p":
		return name == "hydra"
	case "-r":
		return name == "msfconsole"
	default:
		return false
	}
}
