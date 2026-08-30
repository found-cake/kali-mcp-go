package tools

import (
	"net"
	"net/url"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func isLoopbackHost(host string) bool {
	trimmed := strings.Trim(host, "[]")
	if strings.EqualFold(trimmed, "localhost") {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

func TargetWarnings(request any) []string {
	target := RequestTarget(request)
	host := targetHost(target)
	if sqlmap, ok := request.(dto.SQLMapRequest); ok && host == "" {
		host = rawRequestHost(sqlmap.RawRequest)
	}
	if !isLoopbackHost(host) {
		return nil
	}
	return []string{"loopback target refers to the kali-server runtime; call resolve_target to inspect Docker-host and gateway candidates"}
}

func RequestTarget(request any) string {
	switch value := request.(type) {
	case dto.MetasploitRequest:
		return value.Target
	case dto.NmapRequest:
		return value.Target
	case dto.GobusterRequest:
		return value.URL
	case dto.DirbRequest:
		return value.URL
	case dto.NiktoRequest:
		return value.Target
	case dto.SQLMapRequest:
		if value.URL != "" {
			return value.URL
		}
		return rawRequestHost(value.RawRequest)
	case dto.HydraRequest:
		return value.Target
	case dto.WPScanRequest:
		return value.URL
	case dto.Enum4linuxRequest:
		return value.Target
	case dto.FFUFRequest:
		return value.URL
	case dto.FeroxbusterRequest:
		return value.URL
	case dto.NucleiRequest:
		return value.Target
	case dto.WhatWebRequest:
		return value.Target
	case dto.JWTRequest:
		return value.TargetURL
	case dto.DalfoxRequest:
		return value.Target
	case dto.BrowserRequest:
		return value.URL
	case dto.RetireRequest:
		if value.URL == "" && len(value.ScriptURLs) > 0 {
			return value.ScriptURLs[0]
		}
		return value.URL
	case dto.HTTPRequest:
		return value.URL
	default:
		return ""
	}
}

func IsLoopbackTarget(target string) bool {
	return isLoopbackHost(targetHost(target))
}

func targetHost(target string) string {
	parsed, err := url.Parse(target)
	if err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	host, _, err := net.SplitHostPort(target)
	if err == nil {
		return host
	}
	return strings.Trim(target, "[]")
}

func rawRequestHost(request string) string {
	for line := range strings.Lines(request) {
		name, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "host") {
			return targetHost(strings.TrimSpace(value))
		}
	}
	return ""
}
