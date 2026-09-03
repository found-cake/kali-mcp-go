package streaming

import (
	"bufio"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
)

func TestRunCancelsAndExecutesCleanupsWhenTransportContextEnds(t *testing.T) {
	// Given: an idle execution stream bound to a transport lifecycle context.
	ctx, stopTransport := context.WithCancel(context.Background())
	cancelled := make(chan struct{})
	finished := make(chan struct{})
	var cancelOnce sync.Once
	cleanupCalled := false
	go func() {
		runWithTicker(bufio.NewWriter(&strings.Builder{}), Config{
			Context:  ctx,
			Lines:    make(chan executor.Line),
			Done:     make(chan *executor.Result),
			Cancel:   func() { cancelOnce.Do(func() { close(cancelled) }) },
			Cleanups: []func(){func() { cleanupCalled = true }},
		}, func() ticker { return fakeTicker{ch: make(chan time.Time)} })
		close(finished)
	}()

	// When: the transport detects that its client has disconnected.
	stopTransport()

	// Then: the execution is cancelled and cleanup finishes promptly.
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after transport cancellation")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("execution cancellation was not invoked")
	}
	if !cleanupCalled {
		t.Fatal("stream cleanup was not invoked")
	}
}
