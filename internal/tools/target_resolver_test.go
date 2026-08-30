package tools

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestResolveTargetSplitsDNSAddressesAndPinsReachableHTTPAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}

	result, err := ResolveTarget(context.Background(), dto.ResolveTargetRequest{
		Target:                     "http://localhost:" + port + "/health",
		ConnectTimeoutMilliseconds: 250,
	})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}

	foundReachable := false
	for _, candidate := range result.Candidates {
		if candidate.Host != "localhost" {
			continue
		}
		if candidate.NetworkNamespace != "kali" || !candidate.Selectable {
			t.Fatalf("candidate lacks explicit Kali address provenance: %+v", candidate)
		}
		if net.ParseIP(candidate.NetworkTarget) == nil || len(candidate.ResolvedAddresses) != 1 || candidate.ResolvedAddresses[0] != candidate.NetworkTarget {
			t.Fatalf("candidate did not pin one resolved address: %+v", candidate)
		}
		if candidate.AddressFamily != "ipv4" && candidate.AddressFamily != "ipv6" {
			t.Fatalf("candidate lacks address family: %+v", candidate)
		}
		if candidate.Reachable {
			foundReachable = true
			if candidate.HTTPProbe == nil || candidate.HTTPProbe.StatusCode != http.StatusNoContent || candidate.HTTPProbe.BodySHA256 == "" || candidate.HTTPProbe.ServiceFingerprint == "" {
				t.Fatalf("reachable URL lacks HTTP evidence: %+v", candidate)
			}
			if candidate.NetworkTarget != "127.0.0.1" || candidate.Target != "http://127.0.0.1:"+port+"/health" {
				t.Fatalf("reachable candidate was not pinned to the tested IPv4 address: %+v", candidate)
			}
		}
	}
	if !foundReachable {
		t.Fatalf("expected an address-level reachable candidate: %+v", result.Candidates)
	}
}

func TestRecommendTargetCandidate_prefers_explicit_Docker_mapping_for_equivalent_services(t *testing.T) {
	// Given: loopback is unreachable while Docker-host and gateway mappings expose the same HTTP service fingerprint.
	candidates := []dto.TargetCandidate{
		{Target: "http://127.0.0.1:3000/", Scope: dto.TargetScopeKaliRuntime},
		{Target: "http://192.168.65.254:3000/", Scope: dto.TargetScopeDockerHost, Reachable: true, AddressFamily: "ipv4", HTTPProbe: &dto.TargetHTTPProbeEvidence{ServiceFingerprint: "same-service"}},
		{Target: "http://172.17.0.1:3000/", Scope: dto.TargetScopeDefaultGateway, Reachable: true, AddressFamily: "ipv4", HTTPProbe: &dto.TargetHTTPProbeEvidence{ServiceFingerprint: "same-service"}},
	}

	// When: the resolver computes a non-binding recommendation.
	recommended, basis, ok := recommendTargetCandidate(candidates)

	// Then: Docker host is the clear default option, but no target has been rewritten or selected.
	if !ok || recommended.Target != "http://192.168.65.254:3000/" || basis != "equivalent_reachable_mappings_prefer_docker_host" {
		t.Fatalf("unexpected recommendation: candidate=%+v basis=%q ok=%t", recommended, basis, ok)
	}
	if candidates[0].Target != "http://127.0.0.1:3000/" {
		t.Fatalf("original candidate was rewritten: %+v", candidates)
	}
}

func TestResolveTargetReportsReachableRuntimeCandidate(t *testing.T) {
	// Given: a service listening inside the current Kali runtime.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go acceptAndClose(listener)
	port := listener.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("http://127.0.0.1:%d/status", port)

	// When: the dedicated resolver inspects the target.
	result, err := ResolveTarget(context.Background(), dto.ResolveTargetRequest{
		Target:                     target,
		ConnectTimeoutMilliseconds: 100,
	})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}

	// Then: it preserves the target and reports the runtime candidate as reachable.
	if result.OriginalTarget != target || !result.Loopback {
		t.Fatalf("unexpected resolution: %+v", result)
	}
	if len(result.Candidates) == 0 {
		t.Fatal("expected at least one target candidate")
	}
	candidate := result.Candidates[0]
	if candidate.Target != target || candidate.Scope != dto.TargetScopeKaliRuntime || !candidate.Probed || !candidate.Reachable {
		t.Fatalf("unexpected runtime candidate: %+v", candidate)
	}
	if candidate.BrowserTarget != target || candidate.NetworkTarget != "127.0.0.1" {
		t.Fatalf("unexpected tool-specific targets: %+v", candidate)
	}
	if candidate.Probe == nil || candidate.Probe.Type != dto.TargetProbeTCPConnect || candidate.Probe.Address == "" || candidate.Probe.Port != port {
		t.Fatalf("missing TCP reachability evidence: %+v", candidate.Probe)
	}
	if result.RecommendedBrowserTarget != target || result.RecommendedNetworkTarget != "127.0.0.1" || result.RecommendedNetworkPort != port {
		t.Fatalf("unexpected recommended tool targets: %+v", result)
	}
	if !candidate.Recommended || result.RecommendationBasis != "only_reachable_candidate" {
		t.Fatalf("recommended candidate is not explicit in the result: candidate=%+v result=%+v", candidate, result)
	}
}

func TestProbeErrorCodeClassifiesConnectionRefusal(t *testing.T) {
	// Given: a TCP dial failure caused by an explicitly refused connection.
	err := &net.OpError{Op: "dial", Err: fmt.Errorf("connect: %w", syscall.ECONNREFUSED)}

	// When: the resolver classifies the reachability failure.
	code := probeErrorCode(err)

	// Then: callers receive a stable reason instead of parsing operating-system text.
	if code != dto.TargetProbeConnectionRefused {
		t.Fatalf("unexpected probe error code: %s", code)
	}
}

func acceptAndClose(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.Close()
	}
}

func TestResolveTargetUsesSchemeDefaultPort(t *testing.T) {
	// Given: an HTTPS loopback target without an explicit port.
	// When: the resolver parses the address.
	result, err := ResolveTarget(context.Background(), dto.ResolveTargetRequest{
		Target:                     "https://127.0.0.1/status",
		ConnectTimeoutMilliseconds: int((10 * time.Millisecond) / time.Millisecond),
	})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}

	// Then: it probes the HTTPS default port while preserving the original URL.
	if len(result.Candidates) == 0 || result.Candidates[0].Port != 443 || result.Candidates[0].Target != "https://127.0.0.1/status" {
		t.Fatalf("unexpected candidate: %+v", result.Candidates)
	}
}

func TestCandidateHostsIgnoreLegacyLoopbackEnvironment(t *testing.T) {
	// Given: a legacy loopback host environment override.
	t.Setenv("KALI_MCP_LOOPBACK_HOST", "192.0.2.1")

	// When: loopback candidates are discovered.
	candidates := candidateHosts("127.0.0.1", true)

	// Then: the environment value is not treated as a target candidate.
	for _, candidate := range candidates {
		if candidate.host == "192.0.2.1" {
			t.Fatalf("legacy environment candidate leaked into resolver: %+v", candidates)
		}
	}
}
