package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestHTTPRequestUsesTargetContextAndRedactsResponse(t *testing.T) {
	// Given: an authorized local HTTP target and a signed browser context.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Set-Cookie", "session=server-secret")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
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

	// Then: transport status is structured, provenance is verified, and cookies are masked.
	if response.StatusCode != http.StatusOK || result.HTTPResponse == nil || result.HTTPResponse.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected HTTP result: status=%d result=%+v", response.StatusCode, result)
	}
	if result.Target == nil || !result.Target.Verified || result.HTTPRequests == nil || *result.HTTPRequests != 1 {
		t.Fatalf("missing verified request metadata: %+v", result)
	}
	if result.HTTPResponse.Headers.Get("Set-Cookie") != "[REDACTED]" || len(result.Artifacts) != 1 {
		t.Fatalf("response was not protected: %+v", result)
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
