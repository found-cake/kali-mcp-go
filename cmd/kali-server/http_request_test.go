package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

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
	context, err := signTargetContext("secret-token", targetContextClaims{
		ResolutionID:  "resolution-1",
		Original:      "http://127.0.0.1:3000/",
		BrowserTarget: target.URL,
		NetworkTarget: "127.0.0.1",
		ExpiresAt:     now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sign target context: %v", err)
	}
	app := newApp("secret-token", false, defaultMaxConcurrentExecutions, t.Logf)
	body, err := json.Marshal(dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{TargetContext: context},
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

func TestSummarizeHTTPResponsePreservesSensitiveJSONAndLocationValues(t *testing.T) {
	// Given: a JSON response with nested credentials, a JavaScript stack, and a credential-bearing redirect.
	original := []byte(`{"ok":false,"token":"response-secret","profile":{"password":"hidden"},"stack":"Error: failed\n    at login (app.js:1:1)"}`)
	headers := http.Header{"Content-Type": []string{"application/json"}, "Location": []string{"/login?token=response-secret"}}

	// When: the body and response headers are summarized.
	summary := summarizeHTTPResponse(httpResponseSummaryInput{
		Body: original, Headers: headers, UTF8: true,
	})

	// Then: raw values remain while detection metadata and body identity stay available.
	if !strings.Contains(summary.BodyExcerpt, "response-secret") || !strings.Contains(summary.BodyExcerpt, "hidden") {
		t.Fatalf("response evidence was altered: summary=%+v", summary)
	}
	if !summary.SensitiveDataSuspected || !summary.StackTraceSuspected || summary.BodySHA256 == "" || !slices.Equal(summary.JSONKeys, []string{"ok", "profile", "stack", "token"}) || summary.Location != "/login?token=response-secret" {
		t.Fatalf("unexpected response summary: %+v", summary)
	}
}

func TestHTTPClientRejectsCrossOriginRedirect(t *testing.T) {
	// Given: a target that redirects to another origin.
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	client := newHTTPClient(dto.HTTPRequest{URL: source.URL, FollowRedirects: true})

	// When: the bounded client processes the redirect.
	response, err := client.Get(source.URL)
	if response != nil {
		response.Body.Close()
	}

	// Then: the redirect cannot expand the selected target origin.
	if err == nil {
		t.Fatal("expected cross-origin redirect to be rejected")
	}
}
