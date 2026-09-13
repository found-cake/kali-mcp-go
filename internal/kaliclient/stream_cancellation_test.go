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
