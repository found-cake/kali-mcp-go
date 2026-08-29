package tools

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const loopbackHostEnv = "KALI_MCP_LOOPBACK_HOST"

func rewriteLoopbackTarget(target string) string {
	alias := loopbackAlias()
	if alias == "" {
		return target
	}
	parsed, err := url.Parse(target)
	if err == nil && parsed.Host != "" && isLoopbackHost(parsed.Hostname()) {
		port := parsed.Port()
		parsed.Host = alias
		if port != "" {
			parsed.Host = net.JoinHostPort(alias, port)
		}
		return parsed.String()
	}
	if isLoopbackHost(target) {
		return alias
	}
	host, port, err := net.SplitHostPort(target)
	if err == nil && isLoopbackHost(host) {
		return net.JoinHostPort(alias, port)
	}
	return target
}

func loopbackAlias() string {
	configured := strings.TrimSpace(os.Getenv(loopbackHostEnv))
	if configured == "" || net.ParseIP(configured) != nil {
		return configured
	}
	addresses, err := net.LookupIP(configured)
	if err != nil {
		return configured
	}
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return configured
}

func rewriteRawRequestLoopback(request string) string {
	separator := "\n"
	if strings.Contains(request, "\r\n") {
		separator = "\r\n"
	}
	lines := strings.Split(request, separator)
	for index, line := range lines {
		name, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "host") {
			lines[index] = name + ": " + rewriteLoopbackTarget(strings.TrimSpace(value))
		}
	}
	return strings.Join(lines, separator)
}

func isLoopbackHost(host string) bool {
	trimmed := strings.Trim(host, "[]")
	if strings.EqualFold(trimmed, "localhost") {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

func TargetWarnings(request any) []string {
	if strings.TrimSpace(os.Getenv(loopbackHostEnv)) == "" {
		return nil
	}
	var target string
	switch value := request.(type) {
	case dto.NmapRequest:
		target = value.Target
	case dto.GobusterRequest:
		target = value.URL
	case dto.DirbRequest:
		target = value.URL
	case dto.NiktoRequest:
		target = value.Target
	case dto.SQLMapRequest:
		target = value.URL
		if value.RawRequest != "" && value.RawRequest != rewriteRawRequestLoopback(value.RawRequest) {
			return loopbackWarning()
		}
	case dto.HydraRequest:
		target = value.Target
	case dto.WPScanRequest:
		target = value.URL
	case dto.Enum4linuxRequest:
		target = value.Target
	case dto.FFUFRequest:
		target = value.URL
	case dto.FeroxbusterRequest:
		target = value.URL
	case dto.NucleiRequest:
		target = value.Target
	case dto.WhatWebRequest:
		target = value.Target
	case dto.JWTRequest:
		target = value.TargetURL
	case dto.DalfoxRequest:
		target = value.Target
	case dto.BrowserRequest:
		target = value.URL
	case dto.RetireRequest:
		target = value.URL
	}
	if target == rewriteLoopbackTarget(target) {
		return nil
	}
	return loopbackWarning()
}

func loopbackWarning() []string {
	return []string{fmt.Sprintf("container loopback target translated through %s to %s", loopbackHostEnv, loopbackAlias())}
}
