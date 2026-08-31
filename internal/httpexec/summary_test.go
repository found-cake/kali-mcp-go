package httpexec

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

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
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusFound)
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
