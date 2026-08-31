package streaming

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type fakeTicker struct {
	ch <-chan time.Time
}

func (ticker fakeTicker) Chan() <-chan time.Time { return ticker.ch }
func (ticker fakeTicker) Stop()                  {}

type failingWriter struct {
	writes int
}

func (writer *failingWriter) WriteString(string) (int, error) {
	writer.writes++
	return 0, fmt.Errorf("forced write failure")
}

func (writer *failingWriter) Flush() error { return nil }

func TestRunStreamsLineBeforeDone(t *testing.T) {
	// Given: one output line followed by a successful terminal result.
	lines := make(chan executor.Line, 1)
	done := make(chan *executor.Result, 1)
	lines <- executor.Line{Stream: "stdout", Text: "hello"}
	close(lines)
	done <- &executor.Result{ReturnCode: 0}
	close(done)
	buffer := &strings.Builder{}

	// When: the transport-neutral stream state machine runs.
	Run(bufio.NewWriter(buffer), Config{
		CallID: "call-1", Lines: lines, Done: done, HeartbeatInterval: time.Hour,
	})

	// Then: the line precedes one correlated terminal event.
	events := parseEvents(t, buffer.String())
	if len(events) != 2 || events[0].Line != "hello" || events[0].CallID != "call-1" || !events[1].Done || events[1].CallID != "call-1" {
		t.Fatalf("unexpected stream events: %+v", events)
	}
}

func TestRunEmitsHeartbeatBeforeDone(t *testing.T) {
	// Given: an idle stream and a controllable heartbeat ticker.
	lines := make(chan executor.Line)
	done := make(chan *executor.Result, 1)
	heartbeats := make(chan time.Time)
	tickerReady := make(chan struct{})
	finished := make(chan struct{})
	buffer := &strings.Builder{}
	go func() {
		runWithTicker(bufio.NewWriter(buffer), Config{CallID: "call-1", Lines: lines, Done: done}, func() ticker {
			close(tickerReady)
			return fakeTicker{ch: heartbeats}
		})
		close(finished)
	}()

	// When: one heartbeat arrives before the terminal result.
	<-tickerReady
	heartbeats <- time.Now()
	close(lines)
	done <- &executor.Result{ReturnCode: 0}
	close(done)
	<-finished

	// Then: the heartbeat is serialized before the done event.
	events := parseEvents(t, buffer.String())
	if len(events) != 2 || !events[0].Heartbeat || !events[1].Done {
		t.Fatalf("unexpected heartbeat events: %+v", events)
	}
}

func TestRunCancelsAndExecutesCleanupsOnWriteError(t *testing.T) {
	// Given: a writer failure with two ordered cleanup callbacks.
	lines := make(chan executor.Line, 1)
	lines <- executor.Line{Stream: "stdout", Text: "hello"}
	writer := &failingWriter{}
	cancelled := make(chan struct{})
	var cancelOnce sync.Once
	cleanupOrder := make([]string, 0, 2)
	config := Config{
		Lines: lines, Done: make(chan *executor.Result),
		Cancel: func() { cancelOnce.Do(func() { close(cancelled) }) },
		Cleanups: []func(){
			func() { cleanupOrder = append(cleanupOrder, "first") },
			func() { cleanupOrder = append(cleanupOrder, "second") },
		},
	}

	// When: the first stream payload cannot be written.
	runWithTicker(writer, config, func() ticker { return fakeTicker{ch: make(chan time.Time)} })
	close(lines)

	// Then: cancellation and caller cleanup order are preserved.
	select {
	case <-cancelled:
	default:
		t.Fatal("expected cancellation after write failure")
	}
	if writer.writes != 1 || len(cleanupOrder) != 2 || cleanupOrder[0] != "first" || cleanupOrder[1] != "second" {
		t.Fatalf("unexpected write or cleanup state: writes=%d cleanups=%v", writer.writes, cleanupOrder)
	}
}

func TestRunWritesFallbackWhenDoneClosesWithoutValue(t *testing.T) {
	// Given: both producer channels close without a terminal result.
	lines := make(chan executor.Line)
	done := make(chan *executor.Result)
	close(lines)
	close(done)
	buffer := &strings.Builder{}

	// When: the stream state machine reaches the empty terminal state.
	runWithTicker(bufio.NewWriter(buffer), Config{Lines: lines, Done: done}, func() ticker {
		return fakeTicker{ch: make(chan time.Time)}
	})

	// Then: one valid fallback event describes the missing result.
	events := parseEvents(t, buffer.String())
	if len(events) != 1 || !events[0].Done || events[0].ReturnCode == nil || *events[0].ReturnCode != -1 || !strings.Contains(events[0].Error, "without result") {
		t.Fatalf("unexpected fallback event: %+v", events)
	}
}

func TestWriteDoneFallbackEscapesJSONSafely(t *testing.T) {
	// Given: a fallback error containing a JSON control character.
	buffer := &strings.Builder{}
	writer := bufio.NewWriter(buffer)

	// When: the fallback event is serialized.
	writeStreamDoneFallback(writer, "bad\x00value")

	// Then: the decoded value round-trips while the payload remains escaped.
	events := parseEvents(t, buffer.String())
	if len(events) != 1 || events[0].Error != "bad\x00value" || !strings.Contains(buffer.String(), `\u0000`) {
		t.Fatalf("unexpected escaped fallback: events=%+v payload=%q", events, buffer.String())
	}
}

func TestTerminalStreamErrorRemovesAlreadyStreamedPrefix(t *testing.T) {
	// Given: stderr whose first line was already emitted as a stream event.
	result := &executor.Result{ReturnCode: 1, Stderr: "warn line\n\nwait: process interrupted"}

	// When: the terminal-only error is derived.
	got := terminalStreamError(result, "warn line\n")

	// Then: only the unstreamed process error remains.
	if got != "wait: process interrupted" {
		t.Fatalf("unexpected terminal error: %q", got)
	}
}

func parseEvents(t *testing.T, payload string) []dto.StreamEvent {
	t.Helper()
	chunks := strings.Split(strings.TrimSpace(payload), "\n\n")
	events := make([]dto.StreamEvent, 0, len(chunks))
	for _, chunk := range chunks {
		var event dto.StreamEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(chunk, "data: ")), &event); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		events = append(events, event)
	}
	return events
}
