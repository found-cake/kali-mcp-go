package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

type streamTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type streamWriter interface {
	WriteString(s string) (int, error)
	Flush() error
}

type realStreamTicker struct {
	*time.Ticker
}

func (t *realStreamTicker) Chan() <-chan time.Time {
	return t.C
}

func newStreamTicker(interval time.Duration) streamTicker {
	return &realStreamTicker{Ticker: time.NewTicker(interval)}
}

func terminalStreamError(result *executor.Result, streamedStderr string) string {
	if result == nil || result.ReturnCode == 0 || result.Stderr == "" {
		return ""
	}

	terminalErr := result.Stderr
	if streamedStderr != "" && strings.HasPrefix(terminalErr, streamedStderr) {
		terminalErr = strings.TrimPrefix(terminalErr, streamedStderr)
	}

	return strings.TrimLeft(terminalErr, "\n")
}

func sendToolStreamWithCancel(c fiber.Ctx, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, cleanups ...func()) error {
	return sendToolStreamWithTicker(c, lines, done, cancel, func() streamTicker {
		return newStreamTicker(streamHeartbeatInterval)
	}, cleanups...)
}

func sendToolStreamWithTicker(c fiber.Ctx, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, tickerFactory func() streamTicker, cleanups ...func()) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("X-Accel-Buffering", "no")
	callID := callIDFromContext(c)

	return c.SendStreamWriter(func(w *bufio.Writer) {
		streamRun{lines: lines, done: done, cancel: cancel, tickerFactory: tickerFactory, cleanups: cleanups, callID: callID}.run(w)
	})
}

func runSendToolStream(w streamWriter, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, tickerFactory func() streamTicker, cleanups ...func()) {
	streamRun{lines: lines, done: done, cancel: cancel, tickerFactory: tickerFactory, cleanups: cleanups}.run(w)
}

type streamRun struct {
	lines         <-chan executor.Line
	done          <-chan *executor.Result
	cancel        context.CancelFunc
	tickerFactory func() streamTicker
	cleanups      []func()
	callID        string
}

func (s streamRun) run(w streamWriter) {
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

	for linesCh != nil || doneCh != nil {
		var resultCh <-chan *executor.Result
		if linesCh == nil {
			resultCh = doneCh
		}

		select {
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
				writeStreamDoneFallback(w, "internal error: failed to encode stream event")
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
			writeStreamDoneEvent(w, result, streamedStderr.String())
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
				writeStreamDoneFallback(w, "internal error: failed to encode heartbeat event")
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
		writeStreamDoneFallback(w, "internal error: stream ended without result")
	}
}

func writeStreamDoneEvent(w streamWriter, result *executor.Result, streamedStderr string) {
	if result == nil {
		writeStreamDoneFallback(w, "internal error: missing stream result")
		return
	}
	returnCode := result.ReturnCode
	doneEvent := dto.StreamEvent{
		CallID:             result.CallID,
		Done:               true,
		ReturnCode:         &returnCode,
		TimedOut:           result.TimedOut,
		Cancelled:          result.Cancelled,
		HTTPRequests:       result.HTTPRequests,
		RequestCountSource: result.RequestCountSource,
		DurationMS:         result.Duration.Milliseconds(),
		Execution: dto.ExecutionMetadata{
			Tool:            result.Tool,
			ToolVersion:     result.ToolVersion,
			ArgvRedacted:    result.ArgvRedacted,
			StartedAt:       result.StartedAt,
			EndedAt:         result.StartedAt.Add(result.Duration),
			TimeoutMS:       result.Timeout.Milliseconds(),
			TimeoutPlanning: result.TimeoutPlanning,
			ProcessStarted:  result.ProcessStarted,
			GracefulStopMS:  result.GracefulStop.Milliseconds(),
			DryRun:          result.DryRun,
			Profile:         result.Policy.Profile,
			MaxRequests:     result.Policy.MaxRequests,
			RateLimit:       result.Policy.RateLimit,
			Concurrency:     result.Policy.Concurrency,
			HealthURL:       result.Policy.HealthURL,
			Max5xxResponses: result.Policy.Max5xxResponses,
			Controls:        result.Controls,
		},
		Target:            result.Target,
		SPABaseline:       result.SPABaseline,
		FalsePositiveRisk: result.FalsePositiveRisk,
		Warnings:          result.Warnings,
		Artifacts:         result.Artifacts,
		Progress:          result.Progress,
		JWTAnalysis:       result.JWTAnalysis,
	}
	if terminalErr := terminalStreamError(result, streamedStderr); terminalErr != "" {
		doneEvent.Error = terminalErr
		doneEvent.Failure = &dto.FailureInfo{
			Code:          result.FailureCode,
			Message:       terminalErr,
			Retryable:     result.TimedOut || result.Cancelled,
			RetryEstimate: &dto.RetryEstimate{MaximumRequests: result.Policy.MaxRequests, TimeoutMS: result.Timeout.Milliseconds()},
		}
	} else if result.FailureCode != "" {
		doneEvent.Failure = &dto.FailureInfo{
			Code:          result.FailureCode,
			Message:       result.FailureCode,
			Retryable:     result.TimedOut || result.Cancelled,
			RetryEstimate: &dto.RetryEstimate{MaximumRequests: result.Policy.MaxRequests, TimeoutMS: result.Timeout.Milliseconds()},
		}
	}
	payload, err := json.Marshal(doneEvent)
	if err != nil {
		writeStreamDoneFallback(w, "internal error: failed to encode done event")
		return
	}
	_ = writeStreamPayload(w, payload)
}

func writeStreamPayload(w streamWriter, payload []byte) error {
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

func writeStreamDoneFallback(w streamWriter, message string) {
	returnCode := -1
	payload, err := json.Marshal(dto.StreamEvent{Done: true, ReturnCode: &returnCode, Error: message})
	if err != nil {
		_, _ = w.WriteString("data: {\"done\":true,\"return_code\":-1,\"error\":\"internal error: failed to encode fallback event\"}\n\n")
		_ = w.Flush()
		return
	}
	_, _ = w.WriteString("data: " + string(payload) + "\n\n")
	_ = w.Flush()
}
