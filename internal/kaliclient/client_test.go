package kaliclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStreamCancelsRemoteExecutionWhenCallerContextEnds(t *testing.T) {
	started := make(chan string, 1)
	cancelled := make(chan string, 1)
	var cancelOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/api/command/stream":
			callID := request.Header.Get(dto.CallIDHeader)
			writer.Header().Set(dto.CallIDHeader, callID)
			writer.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(writer, "data: {\"stream\":\"stdout\",\"line\":\"started\"}\n\n")
			writer.(http.Flusher).Flush()
			started <- callID
			<-request.Context().Done()
		case strings.HasPrefix(request.URL.Path, "/api/calls/") && strings.HasSuffix(request.URL.Path, "/cancel"):
			callID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/api/calls/"), "/cancel")
			cancelOnce.Do(func() { cancelled <- callID })
			writer.WriteHeader(http.StatusAccepted)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx, stop := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := New(server.URL, 30*time.Second, "token").Stream(ctx, "/api/command/stream", map[string]string{"command": "sleep 30"})
		result <- err
	}()
	callID := <-started
	stop()
	if err := <-result; err == nil {
		t.Fatal("cancelled stream returned no error")
	}
	select {
	case cancelledID := <-cancelled:
		if cancelledID != callID {
			t.Fatalf("cancelled call ID=%q want=%q", cancelledID, callID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("remote cancellation request was not observed")
	}
}

func TestTimeoutForBodyUsesConfiguredBaseTimeoutPlusGrace(t *testing.T) {
	t.Parallel()

	client := New("http://example.com", 30*time.Second, "")

	got := client.timeoutForBody(struct{}{})
	want := 35 * time.Second
	if got != want {
		t.Fatalf("expected timeout %s, got %s", want, got)
	}
}

func TestTimeoutForBodyExtendsForLongCommandRequests(t *testing.T) {
	t.Parallel()

	client := New("http://example.com", 30*time.Second, "")

	got := client.timeoutForBody(dto.CommandRequest{Timeout: 90})
	want := 95 * time.Second
	if got != want {
		t.Fatalf("expected timeout %s, got %s", want, got)
	}
}

func TestTimeoutForBodyExtendsForLongStreamToolRequests(t *testing.T) {
	t.Parallel()

	client := New("http://example.com", 30*time.Second, "")

	got := client.timeoutForBody(dto.NmapRequest{Timeout: 90})
	want := 95 * time.Second
	if got != want {
		t.Fatalf("expected timeout %s, got %s", want, got)
	}
}

func TestStreamReturnsServerStatusError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "upstream failed")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	_, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err == nil || !strings.Contains(err.Error(), "server error 500") {
		t.Fatalf("expected server status error, got %v", err)
	}
}

func TestStreamReturnsDecodeErrorOnMalformedEvent(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\"\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	_, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err == nil || !strings.Contains(err.Error(), "stream decode event") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestStreamRequiresDoneEvent(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	_, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err == nil || !strings.Contains(err.Error(), "without done event") {
		t.Fatalf("expected missing done event error, got %v", err)
	}
}

func TestStreamParsesValidEvents(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":0,\"timed_out\":false}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	res, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("expected stdout hello\\n, got %q", res.Stdout)
	}
	if res.Stderr != "" {
		t.Fatalf("expected empty stderr, got %q", res.Stderr)
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected return code 0, got %d", res.ReturnCode)
	}
	if res.TimedOut {
		t.Fatalf("expected timed_out=false")
	}
	if !res.Success {
		t.Fatalf("expected success=true")
	}
	if res.PartialResults {
		t.Fatalf("expected partial_results=false")
	}
}

func TestStreamIgnoresHeartbeatEvents(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"heartbeat\":true}\n\n")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":0}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	res, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("expected stdout hello\\n, got %q", res.Stdout)
	}
}

func TestStreamUsesProvidedPath(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tools/nmap/stream" {
			t.Fatalf("expected request path /api/tools/nmap/stream, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":0,\"timed_out\":false}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	res, err := client.Stream(context.Background(), "/api/tools/nmap/stream", map[string]string{"target": "127.0.0.1"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("expected stdout hello\\n, got %q", res.Stdout)
	}
}

func TestStreamMarksPartialTimedOutResults(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":-1,\"timed_out\":true}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	res, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res.Success {
		t.Fatalf("expected success=false for partial timed out result")
	}
	if !res.PartialResults {
		t.Fatalf("expected partial_results=true")
	}
	if res.ExecutionStatus != dto.ExecutionTimedOut {
		t.Fatalf("expected timed_out execution status, got %q", res.ExecutionStatus)
	}
}

func TestStreamPreservesPartialFailedResultsAndRequestCountSource(t *testing.T) {
	// Given: an SSE stream that performed parsed HTTP requests before failing.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"partial\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":2,\"http_requests\":3,\"request_count_source\":\"parsed\"}\n\n")
	}))
	defer ts.Close()

	// When: the MCP client reconstructs the terminal result.
	client := New(ts.URL, 5*time.Second, "")
	result, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err != nil {
		t.Fatalf("stream result: %v", err)
	}

	// Then: failure does not discard evidence or request-count provenance.
	if !result.PartialResults || result.RequestCountSource != dto.RequestCountParsed || result.HTTPRequests == nil || *result.HTTPRequests != 3 {
		t.Fatalf("unexpected reconstructed metadata: %+v", result)
	}
}

func TestStreamPreservesJWTAnalysisMetadata(t *testing.T) {
	// Given: a terminal stream event containing safe JWT structure metadata.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":0,\"jwt_analysis\":{\"parse_status\":\"parsed\",\"segment_count\":3,\"alg\":\"HS256\",\"claim_names\":[\"sub\"]}}\n\n")
	}))
	defer ts.Close()

	// When: the MCP client reconstructs the tool result.
	client := New(ts.URL, 5*time.Second, "")
	result, err := client.Stream(context.Background(), "/api/tools/jwt/stream", map[string]string{"token": "redacted"})
	if err != nil {
		t.Fatalf("stream result: %v", err)
	}

	// Then: parsing status is retained without requiring the token value.
	if result.JWTAnalysis == nil || result.JWTAnalysis.ParseStatus != dto.JWTParsed || result.JWTAnalysis.Algorithm != "HS256" {
		t.Fatalf("missing JWT analysis metadata: %+v", result.JWTAnalysis)
	}
}

func TestStreamAppendsTerminalDoneErrorToStderr(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":-1,\"timed_out\":false,\"error\":\"wait: process interrupted\"}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	res, err := client.Stream(context.Background(), "/api/command/stream", map[string]string{"command": "id"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(res.Stderr, "wait: process interrupted") {
		t.Fatalf("expected terminal done error in stderr, got %q", res.Stderr)
	}
	if res.Success {
		t.Fatalf("expected success=false for failed result")
	}
}
