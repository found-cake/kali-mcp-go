package tools

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

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
	if result.RecommendedBrowserTarget != target || result.RecommendedNetworkTarget != "127.0.0.1" || result.RecommendedNetworkPort != port {
		t.Fatalf("unexpected recommended tool targets: %+v", result)
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
