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
	if normalized.Target != "192.168.65.254" || normalized.Ports != "3000" {
		t.Fatalf("unexpected network target: %s", normalized.Target)
	}
	if !provenance.Verified || provenance.Original != result.OriginalTarget || provenance.Selected != normalized.Target {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
	if provenance.Scope != dto.TargetScopeDockerHost || provenance.ContextExpiresAt != result.ReceiptExpiresAt || provenance.ExpiresInSeconds != int64((10*time.Minute)/time.Second) {
		t.Fatalf("missing context lifetime provenance: %+v", provenance)
	}
}

func TestTargetContextBindsNetworkToolPorts(t *testing.T) {
	now := time.Date(2026, time.September, 4, 1, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}
	context := result.Candidates[0].TargetContext

	t.Run("Hydra receives signed port", func(t *testing.T) {
		request := dto.HydraRequest{ScanOptions: dto.ScanOptions{TargetContext: context}}
		normalized, err := targeting.ApplyContext("secret", request, now)
		if err != nil || normalized.Port != 3000 {
			t.Fatalf("Hydra port not bound: request=%+v err=%v", normalized, err)
		}
	})

	t.Run("Metasploit receives signed RPORT", func(t *testing.T) {
		request := dto.MetasploitRequest{ScanOptions: dto.ScanOptions{TargetContext: context}}
		normalized, err := targeting.ApplyContext("secret", request, now)
		if err != nil || normalized.Options["RPORT"] != "3000" {
			t.Fatalf("Metasploit RPORT not bound: request=%+v err=%v", normalized, err)
		}
	})

	for _, test := range []struct {
		name      string
		normalize func() (string, error)
	}{
		{name: "Nuclei host form retains port", normalize: func() (string, error) {
			request, err := targeting.ApplyContext("secret", dto.NucleiRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "192.168.65.254",
			}, now)
			return request.Target, err
		}},
		{name: "WhatWeb host form retains port", normalize: func() (string, error) {
			request, err := targeting.ApplyContext("secret", dto.WhatWebRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "192.168.65.254",
			}, now)
			return request.Target, err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := test.normalize()
			if err != nil || target != "http://192.168.65.254:3000/" {
				t.Fatalf("URL-or-host target lost signed port: target=%q err=%v", target, err)
			}
		})
	}

	for _, test := range []struct {
		name    string
		request any
	}{
		{name: "Nmap mismatched port", request: dto.NmapRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Ports: "80"}},
		{name: "Hydra mismatched port", request: dto.HydraRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Port: 22}},
		{name: "Metasploit mismatched port", request: dto.MetasploitRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Options: map[string]string{"RPORT": "8080"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var err error
			switch request := test.request.(type) {
			case dto.NmapRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			case dto.HydraRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			case dto.MetasploitRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			}
			if err == nil || !strings.Contains(err.Error(), "port") {
				t.Fatalf("mismatched port accepted: %v", err)
			}
		})
	}
}

func TestTargetContextRejectsVirtualHostOverrides(t *testing.T) {
	now := time.Date(2026, time.September, 4, 1, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}
	context := result.Candidates[0].TargetContext

	tests := []struct {
		name  string
		apply func() error
	}{
		{name: "HTTP Host", apply: func() error {
			_, err := targeting.ApplyContext("secret", dto.HTTPRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Headers: map[string]string{"Host": "foreign.test"},
			}, now)
			return err
		}},
		{name: "SQLMap Host", apply: func() error {
			_, err := targeting.ApplyContext("secret", dto.SQLMapRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Headers: map[string]string{"host": "foreign.test"}, URL: "",
			}, now)
			return err
		}},
		{name: "JWT Host", apply: func() error {
			_, err := targeting.ApplyContext("secret", dto.JWTRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, RequestHeader: "Host: foreign.test",
			}, now)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.apply(); err == nil || !strings.Contains(err.Error(), "Host") {
				t.Fatalf("virtual-host override accepted: %v", err)
			}
		})
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
