package kaliclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTimeoutForBodyUsesConfiguredBaseTimeoutPlusGrace(t *testing.T) {
	t.Parallel()

	client := New("http://example.com", 30*time.Second)

	got := client.timeoutForBody(struct{}{})
	want := 35 * time.Second
	if got != want {
		t.Fatalf("expected timeout %s, got %s", want, got)
	}
}

func TestTimeoutForBodyExtendsForLongCommandRequests(t *testing.T) {
	t.Parallel()

	client := New("http://example.com", 30*time.Second)

	got := client.timeoutForBody(dto.CommandRequest{Timeout: 90})
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

	client := New(ts.URL, 5*time.Second)
	_, err := client.Stream(context.Background(), map[string]string{"command": "id"})
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

	client := New(ts.URL, 5*time.Second)
	_, err := client.Stream(context.Background(), map[string]string{"command": "id"})
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

	client := New(ts.URL, 5*time.Second)
	_, err := client.Stream(context.Background(), map[string]string{"command": "id"})
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

	client := New(ts.URL, 5*time.Second)
	res, err := client.Stream(context.Background(), map[string]string{"command": "id"})
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

func TestStreamMarksPartialTimedOutResults(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"stream\":\"stdout\",\"line\":\"hello\"}\n\n")
		fmt.Fprint(w, "data: {\"done\":true,\"return_code\":-1,\"timed_out\":true}\n\n")
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second)
	res, err := client.Stream(context.Background(), map[string]string{"command": "id"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success=true for partial timed out result")
	}
	if !res.PartialResults {
		t.Fatalf("expected partial_results=true")
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

	client := New(ts.URL, 5*time.Second)
	res, err := client.Stream(context.Background(), map[string]string{"command": "id"})
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
