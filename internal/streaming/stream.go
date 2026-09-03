package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type ticker interface {
	Chan() <-chan time.Time
	Stop()
}

type Writer interface {
	WriteString(s string) (int, error)
	Flush() error
}

type realTicker struct {
	*time.Ticker
}

func (t *realTicker) Chan() <-chan time.Time {
	return t.C
}

func newTicker(interval time.Duration) ticker {
	return &realTicker{Ticker: time.NewTicker(interval)}
}

type Config struct {
	Context           context.Context
	CallID            string
	Lines             <-chan executor.Line
	Done              <-chan *executor.Result
	Cancel            context.CancelFunc
	HeartbeatInterval time.Duration
	Cleanups          []func()
}

func Run(writer Writer, config Config) {
	runWithTicker(writer, config, func() ticker {
		return newTicker(config.HeartbeatInterval)
	})
}

func runWithTicker(writer Writer, config Config, tickerFactory func() ticker) {
	streamRun{
		context: config.Context, lines: config.Lines, done: config.Done, cancel: config.Cancel,
		tickerFactory: tickerFactory, cleanups: config.Cleanups, callID: config.CallID,
	}.run(writer)
}

type streamRun struct {
	context       context.Context
	lines         <-chan executor.Line
	done          <-chan *executor.Result
	cancel        context.CancelFunc
	tickerFactory func() ticker
	cleanups      []func()
	callID        string
}

func (s streamRun) run(w Writer) {
	// Register in reverse so deferred execution preserves the caller's cleanup order.
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		if s.cleanups[i] != nil {
			defer s.cleanups[i]()
		}
	}
	if s.cancel != nil {
		defer s.cancel()
	}

	ticker := s.tickerFactory()
	defer ticker.Stop()

	var streamedStderr strings.Builder
	progress := dto.ProgressMetadata{Phase: dto.ProgressRunning}
	wroteDone := false
	linesCh := s.lines
	doneCh := s.done
	contextDone := contextDone(s.context)

	for linesCh != nil || doneCh != nil {
		var resultCh <-chan *executor.Result
		if linesCh == nil {
			resultCh = doneCh
		}

		select {
		case <-contextDone:
			if s.cancel != nil {
				s.cancel()
			}
			go drainStreamLines(linesCh)
			return
		case line, ok := <-linesCh:
			if !ok {
				linesCh = nil
				continue
			}
			if line.Stream == "stderr" {
				streamedStderr.WriteString(line.Text)
				streamedStderr.WriteByte('\n')
			}
			if line.Sequence == 0 {
				progress.ObservedOutputItems++
				progress.LastObservedOutput = line.Text
			} else if line.Sequence > progress.ObservedOutputItems {
				progress.ObservedOutputItems = line.Sequence
				progress.LastObservedOutput = line.Text
			}
			progress.Checkpoint = fmt.Sprintf("output-item-%d", progress.ObservedOutputItems)
			eventProgress := progress
			payload, err := json.Marshal(dto.StreamEvent{CallID: s.callID, Stream: line.Stream, Line: line.Text, Progress: &eventProgress})
			if err != nil {
				if s.cancel != nil {
					s.cancel()
				}
				go drainStreamLines(linesCh)
				writeStreamDoneFallback(w, s.callID, "internal error: failed to encode stream event")
				return
			}
			if err := writeStreamPayload(w, payload); err != nil {
				if s.cancel != nil {
					s.cancel()
				}
				go drainStreamLines(linesCh)
				return
			}
		case result, ok := <-resultCh:
			if !ok {
				doneCh = nil
				continue
			}
			if result != nil && result.CallID == "" {
				result.CallID = s.callID
			}
			if result != nil && (result.Progress == nil || result.Progress.ObservedOutputItems < progress.ObservedOutputItems) {
				result.Progress = &progress
				result.FinalizeProgress()
			}
			writeStreamDoneEvent(w, result, streamedStderr.String(), s.callID)
			wroteDone = true
			return
		case <-ticker.Chan():
			eventProgress := progress
			payload, err := json.Marshal(dto.StreamEvent{CallID: s.callID, Heartbeat: true, Progress: &eventProgress})
			if err != nil {
				if s.cancel != nil {
					s.cancel()
				}
				go drainStreamLines(linesCh)
				writeStreamDoneFallback(w, s.callID, "internal error: failed to encode heartbeat event")
				return
			}
			if err := writeStreamPayload(w, payload); err != nil {
				if s.cancel != nil {
					s.cancel()
				}
				go drainStreamLines(linesCh)
				return
			}
		}
	}

	if !wroteDone {
		writeStreamDoneFallback(w, s.callID, "internal error: stream ended without result")
	}
}

func contextDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

func writeStreamPayload(w Writer, payload []byte) error {
	if _, err := w.WriteString("data: " + string(payload) + "\n\n"); err != nil {
		return err
	}
	return w.Flush()
}

func drainStreamLines(lines <-chan executor.Line) {
	if lines == nil {
		return
	}
	for range lines {
	}
}

func writeStreamDoneFallback(w Writer, callID, message string) {
	returnCode := -1
	payload, err := json.Marshal(dto.StreamEvent{CallID: callID, Done: true, ReturnCode: &returnCode, Error: message})
	if err != nil {
		encodedCallID, _ := json.Marshal(callID)
		_, _ = w.WriteString("data: {\"call_id\":" + string(encodedCallID) + ",\"done\":true,\"return_code\":-1,\"error\":\"internal error: failed to encode fallback event\"}\n\n")
		_ = w.Flush()
		return
	}
	_, _ = w.WriteString("data: " + string(payload) + "\n\n")
	_ = w.Flush()
}
