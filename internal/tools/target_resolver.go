package tools

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	defaultConnectTimeout = 500 * time.Millisecond
	maxConnectTimeout     = 5 * time.Second
	dockerHostName        = "host.docker.internal"
)

type parsedTarget struct {
	original     string
	host         string
	port         int
	explicitPort bool
	url          *url.URL
}

type candidateHost struct {
	host  string
	scope dto.TargetScope
}

func ResolveTarget(ctx context.Context, request dto.ResolveTargetRequest) (*dto.TargetResolutionResult, error) {
	parsed, err := parseTarget(request.Target)
	if err != nil {
		return nil, err
	}
	timeout, err := connectTimeout(request.ConnectTimeoutMilliseconds)
	if err != nil {
		return nil, err
	}
	result := &dto.TargetResolutionResult{
		OriginalTarget: parsed.original,
		Loopback:       isLoopbackHost(parsed.host),
	}
	for _, candidate := range candidateHosts(parsed.host, result.Loopback) {
		result.Candidates = append(result.Candidates, inspectCandidateAddresses(ctx, parsed, candidate, timeout)...)
	}
	result.RecommendationBasis = "explicit_selection_required"
	if recommended, basis, ok := recommendTargetCandidate(result.Candidates); ok {
		result.RecommendedTarget = recommended.Target
		result.RecommendedBrowserTarget = recommended.BrowserTarget
		result.RecommendedNetworkTarget = recommended.NetworkTarget
		result.RecommendedNetworkPort = recommended.Port
		result.RecommendationBasis = basis
	}
	for index := range result.Candidates {
		candidate := &result.Candidates[index]
		if candidate.HTTPProbe != nil && candidate.HTTPProbe.ServiceFingerprint != "" {
			groupID := candidate.HTTPProbe.ServiceFingerprint
			if len(groupID) > 16 {
				groupID = groupID[:16]
			}
			candidate.EquivalentServiceGroup = "service_" + groupID
		}
		if result.RecommendedTarget != "" && candidate.Target == result.RecommendedTarget {
			candidate.Recommended = true
			candidate.RecommendationBasis = result.RecommendationBasis
		}
	}
	if result.Loopback {
		result.Warnings = []string{"scan targets are never rewritten; choose a candidate explicitly for the next tool call"}
	}
	return result, nil
}

func parseTarget(target string) (parsedTarget, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return parsedTarget{}, fmt.Errorf("target is required")
	}
	if strings.Contains(trimmed, "://") {
		parsedURL, err := url.Parse(trimmed)
		if err != nil || parsedURL.Hostname() == "" {
			return parsedTarget{}, fmt.Errorf("target must contain a valid URL host")
		}
		port, explicit, err := targetPort(parsedURL.Scheme, parsedURL.Port())
		if err != nil {
			return parsedTarget{}, err
		}
		return parsedTarget{original: trimmed, host: parsedURL.Hostname(), port: port, explicitPort: explicit, url: parsedURL}, nil
	}
	host, portText, err := net.SplitHostPort(trimmed)
	if err == nil {
		port, _, portErr := targetPort("", portText)
		if portErr != nil {
			return parsedTarget{}, portErr
		}
		return parsedTarget{original: trimmed, host: strings.Trim(host, "[]"), port: port, explicitPort: true}, nil
	}
	host = strings.Trim(trimmed, "[]")
	if host == "" {
		return parsedTarget{}, fmt.Errorf("target host is required")
	}
	return parsedTarget{original: trimmed, host: host}, nil
}

func targetPort(scheme, portText string) (int, bool, error) {
	if portText == "" {
		switch strings.ToLower(scheme) {
		case "http":
			return 80, false, nil
		case "https":
			return 443, false, nil
		default:
			return 0, false, nil
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, false, fmt.Errorf("target port must be between 1 and 65535")
	}
	return port, true, nil
}

func connectTimeout(milliseconds int) (time.Duration, error) {
	if milliseconds == 0 {
		return defaultConnectTimeout, nil
	}
	timeout := time.Duration(milliseconds) * time.Millisecond
	if timeout < time.Millisecond || timeout > maxConnectTimeout {
		return 0, fmt.Errorf("connect_timeout_milliseconds must be between 1 and 5000")
	}
	return timeout, nil
}

func candidateHosts(original string, loopback bool) []candidateHost {
	scope := dto.TargetScopeRequested
	if loopback {
		scope = dto.TargetScopeKaliRuntime
	}
	candidates := []candidateHost{{host: original, scope: scope}}
	if !loopback {
		return candidates
	}
	if dockerHostResolvable() && !strings.EqualFold(dockerHostName, original) {
		candidates = append(candidates, candidateHost{host: dockerHostName, scope: dto.TargetScopeDockerHost})
	}
	if gateway := defaultGateway(); gateway != "" && gateway != original {
		candidates = append(candidates, candidateHost{host: gateway, scope: dto.TargetScopeDefaultGateway})
	}
	return candidates
}

func dockerHostResolvable() bool {
	addresses, err := net.LookupIP(dockerHostName)
	return err == nil && len(addresses) > 0
}

func (target parsedTarget) withHost(host string) string {
	if target.url != nil {
		copyURL := *target.url
		copyURL.Host = host
		if target.explicitPort {
			copyURL.Host = net.JoinHostPort(host, strconv.Itoa(target.port))
		} else if strings.Contains(host, ":") {
			copyURL.Host = "[" + strings.Trim(host, "[]") + "]"
		}
		return copyURL.String()
	}
	if target.explicitPort {
		return net.JoinHostPort(host, strconv.Itoa(target.port))
	}
	return host
}
