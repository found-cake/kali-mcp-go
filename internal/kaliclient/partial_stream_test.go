package kaliclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStreamReturnsPartialOutputBeforeParentDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/cancel") {
			writer.WriteHeader(http.StatusAccepted)
			return
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(writer, "data: {\"stream\":\"stdout\",\"line\":\"partial finding\"}\n\n")
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		<-request.Context().Done()
	}))
	defer server.Close()
	parent, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	result, err := New(server.URL, 30*time.Second, "").Stream(parent, "/api/tools/nuclei/stream", dto.NucleiRequest{})

	if !errors.Is(err, context.DeadlineExceeded) || parent.Err() != nil {
		t.Fatalf("stream did not return before its parent deadline: err=%v parent=%v", err, parent.Err())
	}
	if result == nil || result.Stdout != "partial finding\n" || !result.PartialResults {
		t.Fatalf("partial deadline output was discarded: %+v", result)
	}
}

func TestParseToolStreamPreservesOutputWithoutTerminalEvent(t *testing.T) {
	stream := "data: {\"stream\":\"stdout\",\"line\":\"partial finding\"}\n\n"

	result, err := parseToolStream(strings.NewReader(stream), "call_partial")
	if err == nil || !strings.Contains(err.Error(), "without done event") {
		t.Fatalf("expected missing terminal event error, got %v", err)
	}
	if result == nil || result.CallID != "call_partial" || result.Stdout != "partial finding\n" || !result.PartialResults {
		t.Fatalf("partial stream output was discarded: %+v", result)
	}
}

func TestBoundedRequestTimeoutLeavesResponseMargin(t *testing.T) {
	if got := boundedRequestTimeout(305*time.Second, 300*time.Second); got != 295*time.Second {
		t.Fatalf("request timeout = %v, want 295s response margin", got)
	}
	if got := boundedRequestTimeout(90*time.Second, 300*time.Second); got != 90*time.Second {
		t.Fatalf("short request timeout changed: %v", got)
	}
}

func TestPartialStreamResultStartsAsFailed(t *testing.T) {
	accumulator := streamAccumulator{callID: "call_partial", stdout: []string{"finding"}}

	result := accumulator.partialResult()

	if result.ExecutionStatus != dto.ExecutionFailed || result.ReturnCode != -1 || !result.PartialResults {
		t.Fatalf("unexpected interrupted stream result: %+v", result)
	}
}
