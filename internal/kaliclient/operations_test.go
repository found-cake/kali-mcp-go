package kaliclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type observedRequest struct {
	method      string
	path        string
	escapedPath string
	rawQuery    string
	headers     http.Header
	body        []byte
}

func TestClientJSONOperationsPreserveWireContracts(t *testing.T) {
	t.Parallel()

	// Given: a wire peer that records each dedicated JSON operation.
	requests := make(chan observedRequest, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		requests <- observedRequest{
			method: request.Method, path: request.URL.Path, escapedPath: request.URL.EscapedPath(),
			rawQuery: request.URL.RawQuery, headers: request.Header.Clone(), body: body,
		}
		writer.Header().Set(dto.CallIDHeader, "call_from_header")
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/tools/capabilities":
			fmt.Fprint(writer, `{"profiles":[],"tools":[],"wordlists":[]}`)
		case "/api/tools/resolve-target":
			fmt.Fprint(writer, `{"original_target":"http://127.0.0.1:3000","loopback":true,"candidates":[]}`)
		default:
			fmt.Fprint(writer, `{"artifact_id":"artifact/a","content":"page","offset":7,"next_offset":11,"has_more":false,"total_bytes":11}`)
		}
	}))
	defer server.Close()
	client := New(server.URL, 5*time.Second, "secret-token")

	// When: capabilities, target resolution, and artifact paging are called.
	capabilities, err := client.ScanCapabilities(context.Background())
	if err != nil {
		t.Fatalf("scan capabilities: %v", err)
	}
	resolution, err := client.ResolveTarget(context.Background(), dto.ResolveTargetRequest{Target: "http://127.0.0.1:3000"})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	artifact, err := client.ReadArtifact(context.Background(), dto.ArtifactReadRequest{ArtifactID: "artifact/a", Offset: 7, Limit: 512})
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	// Then: every method, path, query, body, auth header, and call ID remains stable.
	capabilitiesRequest := <-requests
	resolutionRequest := <-requests
	artifactRequest := <-requests
	if capabilitiesRequest.method != http.MethodGet || capabilitiesRequest.path != "/api/tools/capabilities" {
		t.Fatalf("unexpected capabilities request: %s %s", capabilitiesRequest.method, capabilitiesRequest.path)
	}
	if resolutionRequest.method != http.MethodPost || resolutionRequest.path != "/api/tools/resolve-target" || resolutionRequest.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected resolution request: %+v", resolutionRequest)
	}
	var resolutionBody dto.ResolveTargetRequest
	if err := json.Unmarshal(resolutionRequest.body, &resolutionBody); err != nil {
		t.Fatalf("decode resolution body: %v", err)
	}
	if resolutionBody.Target != "http://127.0.0.1:3000" {
		t.Fatalf("unexpected resolution body: %+v", resolutionBody)
	}
	if artifactRequest.method != http.MethodGet || artifactRequest.escapedPath != "/api/artifacts/artifact%2Fa/page" || artifactRequest.rawQuery != "limit=512&offset=7" {
		t.Fatalf("unexpected artifact request: %+v", artifactRequest)
	}
	for _, request := range []observedRequest{capabilitiesRequest, resolutionRequest, artifactRequest} {
		if request.headers.Get("Authorization") != "Bearer secret-token" {
			t.Fatalf("missing bearer authorization on %s", request.path)
		}
	}
	if capabilities.CallID != "call_from_header" || resolution.CallID != "call_from_header" || artifact.CallID != "call_from_header" {
		t.Fatalf("call ID fallback changed: capabilities=%q resolution=%q artifact=%q", capabilities.CallID, resolution.CallID, artifact.CallID)
	}
}

func TestClientJSONOperationsPreserveServerErrors(t *testing.T) {
	t.Parallel()

	// Given: an authenticated endpoint returning a structured status error.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set(dto.CallIDHeader, "call_failure")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, `{"error":"bad request"}`)
	}))
	defer server.Close()

	// When: a dedicated JSON operation receives that response.
	_, err := New(server.URL, 5*time.Second, "token").ScanCapabilities(context.Background())

	// Then: status, call ID, and server body remain available to the orchestrator.
	if err == nil || !strings.Contains(err.Error(), `server error 400 (call_id call_failure): {"error":"bad request"}`) {
		t.Fatalf("unexpected server error: %v", err)
	}
}
