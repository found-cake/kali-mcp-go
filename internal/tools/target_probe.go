package tools

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const kaliNetworkNamespace = "kali"

func inspectCandidateAddresses(ctx context.Context, target parsedTarget, candidate candidateHost, timeout time.Duration) []dto.TargetCandidate {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, candidate.host)
	cancel()
	if err != nil || len(addresses) == 0 {
		return []dto.TargetCandidate{unresolvedTargetCandidate(target, candidate, err)}
	}
	results := make([]dto.TargetCandidate, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		resolved := address.IP.String()
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		results = append(results, inspectResolvedAddress(ctx, target, candidate, resolved, timeout))
	}
	if len(results) == 0 {
		return []dto.TargetCandidate{unresolvedTargetCandidate(target, candidate, nil)}
	}
	return results
}

func unresolvedTargetCandidate(target parsedTarget, candidate candidateHost, lookupErr error) dto.TargetCandidate {
	result := newTargetCandidate(target, candidate, candidate.host)
	result.Selectable = false
	if lookupErr != nil {
		result.ProbeError = lookupErr.Error()
	}
	return result
}

func inspectResolvedAddress(ctx context.Context, target parsedTarget, candidate candidateHost, address string, timeout time.Duration) dto.TargetCandidate {
	result := newTargetCandidate(target, candidate, address)
	result.AddressFamily = addressFamily(address)
	result.ResolvedAddresses = []string{address}
	result.Selectable = true
	if target.port == 0 {
		return result
	}
	result.Probed = true
	probeStarted := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	connection, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(address, strconv.Itoa(target.port)))
	cancel()
	result.Probe = &dto.TargetProbeEvidence{
		Type: dto.TargetProbeTCPConnect, Address: address, Port: target.port,
		LatencyMS: time.Since(probeStarted).Milliseconds(),
	}
	if err != nil {
		result.ProbeError = err.Error()
		result.Probe.ErrorCode = probeErrorCode(err)
		return result
	}
	result.Reachable = true
	_ = connection.Close()
	if target.url != nil {
		result.HTTPProbe = inspectHTTPAddress(ctx, result.BrowserTarget, timeout)
	}
	return result
}

func newTargetCandidate(target parsedTarget, candidate candidateHost, address string) dto.TargetCandidate {
	resolvedTarget := target.withHost(address)
	result := dto.TargetCandidate{
		Target: resolvedTarget, NetworkTarget: address, Host: candidate.host, Port: target.port,
		Scope: candidate.scope, NetworkNamespace: kaliNetworkNamespace,
	}
	if target.url != nil {
		result.BrowserTarget = resolvedTarget
	}
	return result
}

func inspectHTTPAddress(ctx context.Context, address string, timeout time.Duration) *dto.TargetHTTPProbeEvidence {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, address, nil)
	if err != nil {
		return &dto.TargetHTTPProbeEvidence{Error: err.Error()}
	}
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return &dto.TargetHTTPProbeEvidence{Error: err.Error()}
	}
	defer response.Body.Close()
	return &dto.TargetHTTPProbeEvidence{StatusCode: response.StatusCode, FinalURL: response.Request.URL.String()}
}

func addressFamily(address string) string {
	ip := net.ParseIP(address)
	if ip != nil && ip.To4() != nil {
		return "ipv4"
	}
	if ip != nil {
		return "ipv6"
	}
	return ""
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
