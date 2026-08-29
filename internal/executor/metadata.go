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
	output, err := exec.CommandContext(versionCtx, name, "--version").CombinedOutput()
	version := "unknown"
	trimmed := strings.TrimSpace(string(output))
	if err == nil && trimmed != "" {
		version, _, _ = strings.Cut(trimmed, "\n")
	}
	versionCache.Store(name, version)
	return version
}

func redactArgs(name string, args []string) []string {
	redacted := append([]string(nil), args...)
	for index := range redacted {
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
	case "-p":
		return name == "hydra"
	default:
		return false
	}
}
