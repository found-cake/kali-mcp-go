package tools

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
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
		result.Candidates = append(result.Candidates, inspectCandidate(ctx, parsed, candidate, timeout))
	}
	if recommended, ok := onlyReachableCandidate(result.Candidates); ok {
		result.RecommendedTarget = recommended.Target
		result.RecommendedBrowserTarget = recommended.BrowserTarget
		result.RecommendedNetworkTarget = recommended.NetworkTarget
		result.RecommendedNetworkPort = recommended.Port
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

func inspectCandidate(ctx context.Context, target parsedTarget, candidate candidateHost, timeout time.Duration) dto.TargetCandidate {
	result := dto.TargetCandidate{
		Target:        target.withHost(candidate.host),
		NetworkTarget: candidate.host,
		Host:          candidate.host,
		Port:          target.port,
		Scope:         candidate.scope,
	}
	if target.url != nil {
		result.BrowserTarget = result.Target
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, candidate.host)
	cancel()
	if err == nil {
		for _, address := range addresses {
			result.ResolvedAddresses = append(result.ResolvedAddresses, address.IP.String())
		}
	}
	if target.port == 0 {
		return result
	}
	result.Probed = true
	probeStarted := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	connection, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(candidate.host, strconv.Itoa(target.port)))
	cancel()
	result.Probe = &dto.TargetProbeEvidence{
		Type: dto.TargetProbeTCPConnect, Address: candidate.host, Port: target.port,
		LatencyMS: time.Since(probeStarted).Milliseconds(),
	}
	if err != nil {
		result.ProbeError = err.Error()
		result.Probe.ErrorCode = probeErrorCode(err)
		return result
	}
	result.Reachable = true
	if host, _, splitErr := net.SplitHostPort(connection.RemoteAddr().String()); splitErr == nil {
		result.Probe.Address = strings.Trim(host, "[]")
	}
	_ = connection.Close()
	return result
}

func probeErrorCode(err error) dto.TargetProbeErrorCode {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return dto.TargetProbeTimeout
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return dto.TargetProbeConnectionRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return dto.TargetProbeHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return dto.TargetProbeNetworkUnreachable
	default:
		return dto.TargetProbeUnknown
	}
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

func onlyReachableCandidate(candidates []dto.TargetCandidate) (dto.TargetCandidate, bool) {
	var recommended dto.TargetCandidate
	found := false
	for _, candidate := range candidates {
		if !candidate.Reachable {
			continue
		}
		if found {
			return dto.TargetCandidate{}, false
		}
		recommended = candidate
		found = true
	}
	return recommended, found
}

func defaultGateway() string {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		gatewayBytes, err := hex.DecodeString(fields[2])
		if err != nil || len(gatewayBytes) != net.IPv4len {
			continue
		}
		return net.IPv4(gatewayBytes[3], gatewayBytes[2], gatewayBytes[1], gatewayBytes[0]).String()
	}
	return ""
}
