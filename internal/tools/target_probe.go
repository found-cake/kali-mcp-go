package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const kaliNetworkNamespace = "kali"

const maximumServiceFingerprintBodyBytes = 64 * 1024

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
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumServiceFingerprintBodyBytes+1))
	if err != nil {
		return &dto.TargetHTTPProbeEvidence{StatusCode: response.StatusCode, FinalURL: response.Request.URL.String(), Error: err.Error()}
	}
	truncated := len(payload) > maximumServiceFingerprintBodyBytes
	if truncated {
		payload = payload[:maximumServiceFingerprintBodyBytes]
	}
	bodyDigest := sha256.Sum256(payload)
	bodySHA256 := hex.EncodeToString(bodyDigest[:])
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	serviceDigest := sha256.Sum256([]byte(strconv.Itoa(response.StatusCode) + "\x00" + contentType + "\x00" + bodySHA256))
	return &dto.TargetHTTPProbeEvidence{
		StatusCode: response.StatusCode, FinalURL: response.Request.URL.String(), ContentType: contentType,
		BodySHA256: bodySHA256, BodyBytes: len(payload), BodyTruncated: truncated,
		ServiceFingerprint: hex.EncodeToString(serviceDigest[:]),
	}
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

func recommendTargetCandidate(candidates []dto.TargetCandidate) (dto.TargetCandidate, string, bool) {
	if candidate, ok := onlyReachableCandidate(candidates); ok {
		return candidate, "only_reachable_candidate", true
	}
	groups := make(map[string][]dto.TargetCandidate)
	for _, candidate := range candidates {
		if candidate.Reachable && candidate.HTTPProbe != nil && candidate.HTTPProbe.ServiceFingerprint != "" {
			groups[candidate.HTTPProbe.ServiceFingerprint] = append(groups[candidate.HTTPProbe.ServiceFingerprint], candidate)
		}
	}
	var recommendation dto.TargetCandidate
	eligibleGroups := 0
	for _, group := range groups {
		var dockerCandidate dto.TargetCandidate
		hasDocker := false
		hasGateway := false
		for _, candidate := range group {
			switch candidate.Scope {
			case dto.TargetScopeDockerHost:
				if !hasDocker || candidate.AddressFamily == "ipv4" {
					dockerCandidate = candidate
				}
				hasDocker = true
			case dto.TargetScopeDefaultGateway:
				hasGateway = true
			}
		}
		if hasDocker && hasGateway {
			recommendation = dockerCandidate
			eligibleGroups++
		}
	}
	if eligibleGroups != 1 {
		return dto.TargetCandidate{}, "", false
	}
	return recommendation, "equivalent_reachable_mappings_prefer_docker_host", true
}
