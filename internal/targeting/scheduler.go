package targeting

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func SchedulerKey(target string, provenance *dto.TargetProvenance) string {
	if provenance != nil && provenance.Verified && provenance.Original != "" {
		if key := schedulerServiceKey(provenance.Original, provenance.Port); key != "" {
			return key
		}
	}
	if key := schedulerServiceKey(target, provenancePort(provenance)); key != "" {
		return key
	}
	if provenance != nil {
		return schedulerServiceKey(provenance.Selected, provenance.Port)
	}
	return ""
}

func schedulerServiceKey(target string, fallbackPort int) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			return ""
		}
		port := fallbackPort
		if parsed.Port() != "" {
			port, _ = strconv.Atoi(parsed.Port())
		} else if port == 0 {
			if strings.EqualFold(parsed.Scheme, "https") {
				port = 443
			} else if strings.EqualFold(parsed.Scheme, "http") {
				port = 80
			}
		}
		return joinSchedulerHostPort(parsed.Hostname(), port)
	}
	host := strings.Trim(strings.TrimSpace(target), "[]")
	port := fallbackPort
	if parsedHost, parsedPort, err := net.SplitHostPort(target); err == nil {
		host = parsedHost
		port, _ = strconv.Atoi(parsedPort)
	}
	return joinSchedulerHostPort(host, port)
}

func joinSchedulerHostPort(host string, port int) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func provenancePort(provenance *dto.TargetProvenance) int {
	if provenance == nil {
		return 0
	}
	return provenance.Port
}
