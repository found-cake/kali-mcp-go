package httpexec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestExecutePreservesHTTPMetadataAndBody(t *testing.T) {
	// Given: a local HTTP endpoint returning structured JSON evidence.
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	request := dto.HTTPRequest{URL: target.URL, Method: http.MethodPost, JSONBody: []byte(`{"name":"alice"}`)}

	// When: the transport-neutral HTTP executor performs the request.
	result := Execute(context.Background(), Input{CallID: "call-1", Request: request})

	// Then: raw evidence and reproducibility metadata remain structured.
	if result.ReturnCode != 0 || result.CallID != "call-1" || result.Stdout != `{"ok":true}` || result.HTTPResponse == nil || result.HTTPResponse.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected HTTP result: %+v", result)
	}
	if result.HTTPRequest == nil || result.HTTPRequest.Method != http.MethodPost || result.HTTPRequest.BodySHA256 == "" || result.HTTPResponse.Summary == nil || result.HTTPResponse.Summary.BodySHA256 == "" {
		t.Fatalf("missing HTTP metadata: request=%+v response=%+v", result.HTTPRequest, result.HTTPResponse)
	}
}

func TestExecuteRejectsCrossOriginRedirect(t *testing.T) {
	// Given: a source endpoint redirecting to a different origin.
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusFound)
	}))
	defer source.Close()

	// When: redirect following is enabled for the request.
	result := Execute(context.Background(), Input{Request: dto.HTTPRequest{URL: source.URL, FollowRedirects: true}})

	// Then: execution fails closed before contacting the foreign origin.
	if result.FailureCode != "http_request_failed" || !strings.Contains(result.Stderr, "cross-origin redirect rejected") {
		t.Fatalf("unexpected redirect result: %+v", result)
	}
}

func TestExecuteTruncatesResponseAtRequestedLimit(t *testing.T) {
	// Given: a response larger than the caller's retained byte limit.
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("abcdef"))
	}))
	defer target.Close()

	// When: execution retains only three response bytes.
	result := Execute(context.Background(), Input{Request: dto.HTTPRequest{URL: target.URL, MaxResponseBytes: 3}})

	// Then: stdout and response metadata explicitly describe the truncation.
	if result.Stdout != "abc" || result.HTTPResponse == nil || !result.HTTPResponse.BodyTruncated || result.HTTPResponse.BodyBytes != 3 {
		t.Fatalf("unexpected truncated result: %+v", result)
	}
}

func TestExecuteUsesVirtualHostWithoutChangingConnectionTarget(t *testing.T) {
	// Given: an HTTP endpoint selected by target context and a separate virtual host value.
	observedHost := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observedHost <- request.Host
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	request := dto.HTTPRequest{
		ScanOptions: dto.ScanOptions{TargetContext: "signed-context"},
		URL:         target.URL,
		VirtualHost: "tenant.example.test",
	}

	// When: the bounded HTTP request is sent.
	result := Execute(context.Background(), Input{Request: request})

	// Then: the selected URL receives the request with only its HTTP Host overridden.
	if result.ReturnCode != 0 || <-observedHost != "tenant.example.test" {
		t.Fatalf("virtual-host request failed: %+v", result)
	}
	if result.HTTPRequest == nil || result.HTTPRequest.Host != "tenant.example.test" || result.HTTPRequest.URL != target.URL {
		t.Fatalf("virtual-host evidence is inconsistent: %+v", result.HTTPRequest)
	}
}

func TestValidateRejectsInvalidMethodAndConflictingBodies(t *testing.T) {
	tests := []struct {
		name    string
		request dto.HTTPRequest
		message string
	}{
		{name: "method", request: dto.HTTPRequest{URL: "http://example.test", Method: "TRACE"}, message: "method must be"},
		{name: "safe profile method", request: dto.HTTPRequest{ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon}, URL: "http://example.test", Method: "DELETE"}, message: "safe-recon"},
		{name: "bodies", request: dto.HTTPRequest{URL: "http://example.test", Body: "text", JSONBody: []byte(`{}`)}, message: "body and json_body"},
		{name: "virtual host without context", request: dto.HTTPRequest{URL: "http://example.test", VirtualHost: "tenant.example.test"}, message: "target_context"},
		{name: "invalid virtual host", request: dto.HTTPRequest{ScanOptions: dto.ScanOptions{TargetContext: "signed"}, URL: "http://example.test", VirtualHost: "bad host"}, message: "virtual_host"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: an HTTP request violating one boundary rule.
			// When: the request is validated before execution.
			err := Validate(test.request)

			// Then: validation returns the existing actionable error.
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
