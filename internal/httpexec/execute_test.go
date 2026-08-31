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

func TestValidateRejectsInvalidMethodAndConflictingBodies(t *testing.T) {
	tests := []struct {
		name    string
		request dto.HTTPRequest
		message string
	}{
		{name: "method", request: dto.HTTPRequest{URL: "http://example.test", Method: "TRACE"}, message: "method must be"},
		{name: "bodies", request: dto.HTTPRequest{URL: "http://example.test", Body: "text", JSONBody: []byte(`{}`)}, message: "body and json_body"},
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
