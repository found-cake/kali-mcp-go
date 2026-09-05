package toolapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSQLMapTargetContextPreservesExplicitNonURLSource(t *testing.T) {
	// Given: a signed web target and each supported non-URL SQLMap source.
	now := time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}
	requestFile := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(requestFile, []byte("GET / HTTP/1.1\r\nHost: 192.168.65.254:3000\r\n\r\n"), 0o600); err != nil {
		t.Fatalf("write request file: %v", err)
	}
	tests := []dto.SQLMapRequest{
		{RawRequest: "GET / HTTP/1.1\r\nHost: 192.168.65.254:3000\r\n\r\n"},
		{RawRequest: "GET http://192.168.65.254:3000/rest/products HTTP/1.1\r\nHost: 192.168.65.254:3000\r\n\r\n"},
		{RequestFile: requestFile},
	}

	for _, request := range tests {
		request.ScanOptions.TargetContext = result.Candidates[0].TargetContext

		// When: the target context is applied before SQLMap validation.
		normalized, err := targeting.ApplyContext("secret", request, now)
		if err != nil {
			t.Fatalf("apply target context: %v", err)
		}

		// Then: provenance remains signed without introducing a second URL source.
		if normalized.URL != "" || normalized.RawRequest != request.RawRequest || normalized.RequestFile != request.RequestFile {
			t.Fatalf("SQLMap source changed: %+v", normalized)
		}
		if err := validateSQLMapRequest(normalized); err != nil {
			t.Fatalf("validate SQLMap source: %v", err)
		}
		provenance, err := targeting.ResolveProvenance(normalized, "secret", now)
		if err != nil {
			t.Fatalf("resolve SQLMap provenance: %v", err)
		}
		if provenance == nil || !provenance.Verified || provenance.Selected != "192.168.65.254" {
			t.Fatalf("missing verified SQLMap provenance: %+v", provenance)
		}
	}
}

func TestSQLMapTargetContextRejectsMismatchedNonURLSource(t *testing.T) {
	// Given: a signed target context and raw/file requests naming another destination.
	now := time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}
	requestFile := filepath.Join(t.TempDir(), "foreign.txt")
	if err := os.WriteFile(requestFile, []byte("GET / HTTP/1.1\r\nHost: 198.51.100.20:3000\r\n\r\n"), 0o600); err != nil {
		t.Fatalf("write request file: %v", err)
	}
	absoluteRequestFile := filepath.Join(t.TempDir(), "absolute-foreign.txt")
	if err := os.WriteFile(absoluteRequestFile, []byte("GET http://198.51.100.20:3000/ HTTP/1.1\r\nHost: 192.168.65.254:3000\r\n\r\n"), 0o600); err != nil {
		t.Fatalf("write absolute request file: %v", err)
	}
	tests := []dto.SQLMapRequest{
		{RawRequest: "GET / HTTP/1.1\r\nHost: 198.51.100.20:3000\r\n\r\n"},
		{RawRequest: "GET / HTTP/1.1\r\nHost: 192.168.65.254:9999\r\n\r\n"},
		{RawRequest: "GET http://198.51.100.20:3000/ HTTP/1.1\r\nHost: 192.168.65.254:3000\r\n\r\n"},
		{RawRequest: "CONNECT 198.51.100.20:443 HTTP/1.1\r\nHost: 192.168.65.254:3000\r\n\r\n"},
		{RequestFile: requestFile},
		{RequestFile: absoluteRequestFile},
	}

	for _, request := range tests {
		request.ScanOptions.TargetContext = result.Candidates[0].TargetContext

		// When: the foreign SQLMap source is bound to the selected context.
		normalized, err := targeting.ApplyContext("secret", request, now)
		if err == nil {
			_, err = targeting.ResolveProvenance(normalized, "secret", now)
		}

		// Then: the server rejects the source before SQLMap executes it.
		if err == nil || !strings.Contains(err.Error(), "does not match target_context") {
			t.Fatalf("mismatched SQLMap source accepted: %v", err)
		}
	}
}

func TestSQLMapRequestFileLoopbackRequiresResolution(t *testing.T) {
	t.Parallel()

	requestFile := filepath.Join(t.TempDir(), "loopback.txt")
	if err := os.WriteFile(requestFile, []byte("GET /?id=* HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n"), 0o600); err != nil {
		t.Fatalf("write request file: %v", err)
	}
	request := dto.SQLMapRequest{RequestFile: requestFile}
	provenance, err := targeting.ResolveProvenance(request, "secret", time.Now())
	if err == nil || !strings.Contains(err.Error(), "target resolution is required") || provenance != nil {
		t.Fatalf("loopback request file bypassed resolution: provenance=%+v err=%v", provenance, err)
	}
}
