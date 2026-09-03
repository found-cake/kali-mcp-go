package toolapi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestPrepareScanExecutionRequiresVerifiedContextForCredentialAttack(t *testing.T) {
	app := fiber.New()
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.HydraRequest{
			Target: "192.0.2.10", Service: "ssh", Username: "root", Password: "test",
		}, []string{"hydra", "192.0.2.10", "ssh"})
		if err != nil {
			return httpapi.BadRequest(c, err.Error())
		}
		defer plan.release()
		return c.SendStatus(fiber.StatusNoContent)
	})

	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("credential attack accepted an unverified direct target: status=%d", response.StatusCode)
	}
}

func TestTargetContextSelectsNetworkFormWithoutServerState(t *testing.T) {
	// Given: an explicitly resolved Docker-host candidate and a signed context.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{
			{
				BrowserTarget: "http://192.168.65.254:3000/",
				NetworkTarget: "192.168.65.254",
				Host:          "host.docker.internal",
				Port:          3000,
				Scope:         dto.TargetScopeDockerHost,
				Selectable:    true,
			},
		},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}

	// When: Nmap supplies only the selected candidate context.
	request := dto.NmapRequest{ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext}}
	normalized, err := targeting.ApplyContext("secret", request, now)
	if err != nil {
		t.Fatalf("apply target context: %v", err)
	}
	provenance, err := targeting.ResolveProvenance(normalized, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the network form is explicit, verified, and tied to the original target.
	if normalized.Target != "192.168.65.254" {
		t.Fatalf("unexpected network target: %s", normalized.Target)
	}
	if !provenance.Verified || provenance.Original != result.OriginalTarget || provenance.Selected != normalized.Target {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
	if provenance.Scope != dto.TargetScopeDockerHost || provenance.ContextExpiresAt != result.ReceiptExpiresAt || provenance.ExpiresInSeconds != int64((10*time.Minute)/time.Second) {
		t.Fatalf("missing context lifetime provenance: %+v", provenance)
	}
}

func TestTargetContextOriginMismatchExplainsCandidateUsage(t *testing.T) {
	// Given: a signed Docker-host context and a request that repeats the original loopback URL.
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
	request := dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext},
		URL:         result.OriginalTarget,
	}

	// When: the request is constrained to the selected browser origin.
	_, err := targeting.ApplyContext("secret", request, now)

	// Then: rejection identifies the selected browser_target and the URL-omission alternative.
	if err == nil || !strings.Contains(err.Error(), "browser_target http://192.168.65.254:3000/") || !strings.Contains(err.Error(), "omit the request URL") {
		t.Fatalf("origin mismatch lacks actionable guidance: %v", err)
	}
}

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
	tests := []dto.SQLMapRequest{
		{RawRequest: "GET / HTTP/1.1\r\nHost: 198.51.100.20:3000\r\n\r\n"},
		{RawRequest: "GET / HTTP/1.1\r\nHost: 192.168.65.254:9999\r\n\r\n"},
		{RequestFile: requestFile},
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

func TestTargetContextWarnsWhenExpiryIsNear(t *testing.T) {
	// Given: a verified target context with thirty seconds remaining.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://host.docker.internal:3000/", NetworkTarget: "host.docker.internal",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(30*time.Second)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}
	request := dto.NmapRequest{Target: "host.docker.internal", ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext}}

	// When: scan provenance is resolved immediately before execution.
	provenance, err := targeting.ResolveProvenance(request, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the result exposes the remaining lifetime and a machine-readable warning state.
	if !provenance.ExpiringSoon || provenance.ExpiresInSeconds != 30 || len(targeting.Warnings(request, provenance)) == 0 {
		t.Fatalf("missing expiry warning metadata: %+v", provenance)
	}
}

func TestResolutionLifetimeRejectsExcessiveValidity(t *testing.T) {
	// Given: a requested context lifetime above the server maximum.
	// When: the bounded lifetime is parsed.
	_, err := targeting.Lifetime(3601)

	// Then: the resolver rejects the oversized validity window.
	if err == nil {
		t.Fatal("expected excessive target context lifetime to be rejected")
	}
}

func TestRetireScriptURLsStayWithinSelectedBrowserOrigin(t *testing.T) {
	now := time.Now().UTC()
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.0.2.10:3000/", NetworkTarget: "192.0.2.10",
			Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}
	request := dto.RetireRequest{
		ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext},
		ScriptURLs:  []string{"http://192.0.2.10:3000/main.js", "http://192.0.2.10:3000/lazy.js"},
	}
	normalized, err := targeting.ApplyContext("secret", request, now)
	if err != nil {
		t.Fatalf("apply script URL context: %v", err)
	}
	if normalized.URL != "" || len(normalized.ScriptURLs) != 2 {
		t.Fatalf("script URLs were replaced instead of scoped: %+v", normalized)
	}

	request.ScriptURLs = []string{"http://198.51.100.20:3000/foreign.js"}
	if _, err := targeting.ApplyContext("secret", request, now); err == nil {
		t.Fatal("expected cross-origin script URL to be rejected")
	}
}

func TestRetireExplicitScriptURLsRequireTargetContext(t *testing.T) {
	request := dto.RetireRequest{ScriptURLs: []string{"https://example.com/main.js"}}
	if err := validateRetireRequest(request); err == nil || !strings.Contains(err.Error(), "target_context") {
		t.Fatalf("expected target context requirement, got %v", err)
	}
}
