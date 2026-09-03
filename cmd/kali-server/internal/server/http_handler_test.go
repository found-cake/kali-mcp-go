package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestHTTPRequestRejectsMalformedBody(t *testing.T) {
	// Given: the authenticated HTTP tool route and malformed JSON input.
	app := newApp("secret-token", false, httpapi.DefaultMaxConcurrentExecutions, t.Logf)
	t.Cleanup(func() { _ = app.Shutdown() })
	request, err := http.NewRequest(http.MethodPost, "/api/tools/http-request", strings.NewReader(`{`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("Content-Type", "application/json")

	// When: Fiber binds the malformed request at the adapter boundary.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Then: the adapter preserves the existing bad-request mapping.
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(payload), "invalid request body") {
		t.Fatalf("unexpected malformed response: status=%d body=%s", response.StatusCode, payload)
	}
}

func TestHTTPRequestOriginMismatchReturnsCandidateGuidance(t *testing.T) {
	// Given: an authenticated HTTP tool request that repeats the original loopback URL.
	now := time.Now().UTC()
	resolution := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret-token", &resolution, now.Add(time.Hour)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}
	app := newApp("secret-token", false, httpapi.DefaultMaxConcurrentExecutions, t.Logf)
	t.Cleanup(func() { _ = app.Shutdown() })
	body, err := json.Marshal(dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{TargetContext: resolution.Candidates[0].TargetContext},
		URL:         resolution.OriginalTarget,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, "/api/tools/http-request", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("Content-Type", "application/json")

	// When: the request crosses the authenticated HTTP boundary.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Then: HTTP 400 includes the selected browser target and URL-omission alternative.
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(payload), "browser_target http://192.168.65.254:3000/") || !strings.Contains(string(payload), "omit the request URL") {
		t.Fatalf("origin mismatch response lacks guidance: status=%d body=%s", response.StatusCode, payload)
	}
}

func TestHTTPRequestUsesTargetContextAndPreservesResponseByDefault(t *testing.T) {
	// Given: an authorized local HTTP target and a signed browser context.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Set-Cookie", "session=server-secret")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "/next?token=server-secret")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true,"token":"server-secret"}`))
	}))
	defer target.Close()
	now := time.Now().UTC()
	resolution := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: target.URL, NetworkTarget: "127.0.0.1", Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret-token", &resolution, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}
	app := newApp("secret-token", false, httpapi.DefaultMaxConcurrentExecutions, t.Logf)
	body, err := json.Marshal(dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{TargetContext: resolution.Candidates[0].TargetContext},
		Method:      http.MethodPost,
		Headers:     map[string]string{"Authorization": "Bearer request-secret", "X-Test": "visible"},
		JSONBody:    json.RawMessage(`{"name":"alice"}`),
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, "/api/tools/http-request", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("Content-Type", "application/json")

	// When: the dedicated HTTP tool performs the request.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	var result dto.ToolResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	// Then: transport status and provenance are structured without altering the evidence.
	if response.StatusCode != http.StatusOK || result.HTTPResponse == nil || result.HTTPResponse.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected HTTP result: status=%d result=%+v", response.StatusCode, result)
	}
	if result.Target == nil || !result.Target.Verified || result.HTTPRequests == nil || *result.HTTPRequests != 1 {
		t.Fatalf("missing verified request metadata: %+v", result)
	}
	if result.HTTPResponse.Headers.Get("Set-Cookie") != "session=server-secret" || result.HTTPResponse.Headers.Get("Location") != "/next?token=server-secret" || len(result.Artifacts) != 1 {
		t.Fatalf("response was not preserved: %+v", result)
	}
	if result.HTTPRequest == nil || result.HTTPRequest.Method != http.MethodPost || result.HTTPRequest.URL != target.URL || result.HTTPRequest.ContentType != "application/json" {
		t.Fatalf("missing reproducible request metadata: %+v", result.HTTPRequest)
	}
	if result.HTTPRequest.Headers.Get("Authorization") != "Bearer request-secret" || result.HTTPRequest.Headers.Get("X-Test") != "visible" || result.HTTPRequest.BodyBytes != len(`{"name":"alice"}`) || result.HTTPRequest.BodySHA256 == "" {
		t.Fatalf("request metadata was not preserved: %+v", result.HTTPRequest)
	}
	if result.HTTPResponse.Summary == nil || result.HTTPResponse.Summary.BodySHA256 == "" || !strings.Contains(result.Stdout, "server-secret") || !strings.Contains(result.HTTPResponse.Summary.BodyExcerpt, "server-secret") || !slices.Equal(result.HTTPResponse.Summary.JSONKeys, []string{"ok", "token"}) || !result.HTTPResponse.Summary.SensitiveDataSuspected {
		t.Fatalf("response body was not summarized: %+v", result.HTTPResponse.Summary)
	}
	if result.Artifacts[0].RedactionState != dto.ArtifactSensitiveUnredacted {
		t.Fatalf("raw artifact state was not declared: %+v", result.Artifacts[0])
	}
}
