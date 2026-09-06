package toolapi

import (
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

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
		{name: "Dalfox Host", apply: func() error {
			_, err := targeting.ApplyContext("secret", dto.DalfoxRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Headers: map[string]string{"HOST": "foreign.test"},
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

func TestTargetContextRewritesOriginalOriginSubpathToSelectedCandidate(t *testing.T) {
	// Given: a signed Docker-host context and a request using a new path on the original loopback origin.
	now := time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/app/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/app/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}
	request := dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext},
		URL:         "http://127.0.0.1:3000/rest/products?query=apple#details",
	}

	// When: the selected context is applied.
	normalized, err := targeting.ApplyContext("secret", request, now)

	// Then: only the origin is replaced while the caller's path, query, and fragment survive.
	if err != nil || normalized.URL != "http://192.168.65.254:3000/rest/products?query=apple#details" {
		t.Fatalf("original-origin path was not mapped: request=%+v err=%v", normalized, err)
	}
}

func TestTargetContextRejectsForeignWebOrigin(t *testing.T) {
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
		URL:         "http://198.51.100.20:3000/admin",
	}

	_, err := targeting.ApplyContext("secret", request, now)

	if err == nil || !strings.Contains(err.Error(), "browser origin") {
		t.Fatalf("foreign origin was accepted: %v", err)
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
