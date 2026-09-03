package targeting

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestResolutionReceiptRejectsCandidateOutsideResolution(t *testing.T) {
	// Given: a receipt containing one explicitly resolved target.
	now := time.Date(2026, time.August, 29, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget:    "http://127.0.0.1:3000/",
		RecommendedTarget: "http://host.docker.internal:3000/",
		Candidates: []dto.TargetCandidate{
			{Target: "http://host.docker.internal:3000/", Reachable: true, Selectable: true},
		},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}

	// When: a scanner selects a target outside the resolved candidates.
	_, err = verifyResolutionReceipt("secret", issued.Token, "http://192.0.2.10:3000/", now)

	// Then: the receipt is rejected as a target mismatch.
	if !errors.Is(err, errResolutionTargetMismatch) {
		t.Fatalf("expected target mismatch, got %v", err)
	}
}

func TestResolveTargetProvenanceRequiresReceiptForLoopback(t *testing.T) {
	// Given: a loopback scan request without a resolver receipt.
	request := dto.NmapRequest{Target: "127.0.0.1"}

	// When: target provenance is resolved at the execution boundary.
	_, err := ResolveProvenance(request, "secret", time.Now())

	// Then: execution is rejected until resolve_target has been used.
	if !errors.Is(err, errResolutionRequired) {
		t.Fatalf("expected resolution required, got %v", err)
	}
}

func TestResolutionReceiptAllowsPathSpecificScanOnResolvedOrigin(t *testing.T) {
	// Given: a receipt that resolved the root path of a web origin.
	now := time.Date(2026, time.August, 29, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{
			{Target: "http://172.17.0.1:3000/", Reachable: true, Selectable: true},
		},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}

	// When: FFUF selects a path placeholder on that same origin.
	provenance, err := verifyResolutionReceipt("secret", issued.Token, "http://172.17.0.1:3000/FUZZ", now)
	// Then: the path-specific scan remains verified against the resolved origin.
	if err != nil {
		t.Fatalf("verify same-origin path: %v", err)
	}
	if provenance.Selected != "http://172.17.0.1:3000/FUZZ" || !provenance.Verified {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
}

func TestResolutionReceiptRejectsVirtualHostOverride(t *testing.T) {
	now := time.Date(2026, time.September, 4, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			Target: "http://172.17.0.1:3000/", Reachable: true, Selectable: true,
		}},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}
	request := dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{ResolutionReceipt: issued.Token},
		URL:         result.Candidates[0].Target,
		Headers:     map[string]string{"Host": "foreign.test"},
	}
	if _, err := ResolveProvenance(request, "secret", now); err == nil || !strings.Contains(err.Error(), "Host") {
		t.Fatalf("resolution receipt accepted a virtual-host override: %v", err)
	}
}

func TestResolutionReceiptAllowsNetworkFormDerivedFromResolvedWebTarget(t *testing.T) {
	// Given: a resolver candidate with explicit browser and network forms.
	now := time.Date(2026, time.August, 29, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget:           "http://127.0.0.1:3000/",
		RecommendedTarget:        "http://host.docker.internal:3000/",
		RecommendedBrowserTarget: "http://host.docker.internal:3000/",
		RecommendedNetworkTarget: "host.docker.internal",
		RecommendedNetworkPort:   3000,
		Candidates: []dto.TargetCandidate{
			{
				Target:        "http://host.docker.internal:3000/",
				BrowserTarget: "http://host.docker.internal:3000/",
				NetworkTarget: "host.docker.internal",
				Port:          3000,
				Scope:         dto.TargetScopeDockerHost,
				Reachable:     true,
				Selectable:    true,
			},
		},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}

	// When: Nmap selects the resolver-provided network form.
	provenance, err := verifyResolutionReceipt("secret", issued.Token, "host.docker.internal", now)
	// Then: the derived host is verified as the only reachable candidate.
	if err != nil {
		t.Fatalf("verify network target: %v", err)
	}
	if !provenance.Verified || provenance.SelectionReason != "only_reachable_candidate" ||
		provenance.Port != 3000 || provenance.Scope != dto.TargetScopeDockerHost {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
}

func TestResolutionReceiptBindsNetworkToolPort(t *testing.T) {
	now := time.Date(2026, time.September, 4, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach resolution: %v", err)
	}
	receipt := result.ResolutionReceipt

	normalized, err := ApplyContext("secret", dto.NmapRequest{
		ScanOptions: dto.ScanOptions{ResolutionReceipt: receipt}, Target: "192.168.65.254",
	}, now)
	if err != nil || normalized.Ports != "3000" {
		t.Fatalf("receipt port not bound: request=%+v err=%v", normalized, err)
	}

	_, err = ApplyContext("secret", dto.NmapRequest{
		ScanOptions: dto.ScanOptions{ResolutionReceipt: receipt}, Target: "192.168.65.254", Ports: "22",
	}, now)
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("receipt accepted mismatched port: %v", err)
	}
}

func TestAttachResolutionPopulatesReceiptAndCandidateContexts(t *testing.T) {
	// Given: one explicitly selectable resolver candidate.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	expiresAt := now.Add(10 * time.Minute)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://host.docker.internal:3000/",
			NetworkTarget: "host.docker.internal",
			Port:          3000,
			Scope:         dto.TargetScopeDockerHost,
			Selectable:    true,
		}},
	}

	// When: target authorization is attached at the resolver boundary.
	err := AttachResolution("secret", &result, expiresAt)

	// Then: the stateless receipt and candidate context share the requested expiry.
	if err != nil {
		t.Fatalf("attach resolution: %v", err)
	}
	if result.ResolutionID == "" || result.ResolutionReceipt == "" || result.Candidates[0].TargetContext == "" {
		t.Fatalf("missing signed resolution data: %+v", result)
	}
	if !result.ReceiptExpiresAt.Equal(expiresAt) || !result.Candidates[0].ContextExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected expiration metadata: receipt=%s context=%s", result.ReceiptExpiresAt, result.Candidates[0].ContextExpiresAt)
	}
}

func TestLifetimeRejectsExcessiveValidity(t *testing.T) {
	// Given: a requested lifetime above the one-hour server maximum.
	// When: the targeting package parses the requested validity.
	_, err := Lifetime(3601)

	// Then: the existing public error text remains stable.
	if err == nil || err.Error() != "valid_for_seconds must be between 1 and 3600" {
		t.Fatalf("unexpected lifetime error: %v", err)
	}
}

func TestResolutionReceiptRejectsTamperedAndExpiredTokens(t *testing.T) {
	// Given: a valid signed receipt and one that already expired.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates:     []dto.TargetCandidate{{Target: "http://host.docker.internal:3000/", Selectable: true}},
	}
	valid, err := issueResolutionReceiptUntil("secret", result, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("issue valid receipt: %v", err)
	}
	expired, err := issueResolutionReceiptUntil("secret", result, now.Add(-time.Second))
	if err != nil {
		t.Fatalf("issue expired receipt: %v", err)
	}

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{name: "tampered", token: valid.Token + "x", want: errInvalidResolutionReceipt},
		{name: "expired", token: expired.Token, want: errExpiredResolutionReceipt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When: verification receives an invalid receipt state.
			_, err := verifyResolutionReceipt("secret", test.token, result.Candidates[0].Target, now)

			// Then: verification fails closed with the established sentinel.
			if !errors.Is(err, test.want) {
				t.Fatalf("verify receipt: got %v, want %v", err, test.want)
			}
		})
	}
}
