package main

import (
	"bufio"
	"context"
	"encoding/json"
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

	return c.SendStreamWriter(func(w *bufio.Writer) {
		runSendToolStream(w, lines, done, cancel, tickerFactory, cleanups...)
	})
}

func runSendToolStream(w streamWriter, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, tickerFactory func() streamTicker, cleanups ...func()) {
	// Register in reverse so deferred execution preserves the caller's cleanup order.
	for i := len(cleanups) - 1; i >= 0; i-- {
		if cleanups[i] != nil {
			defer cleanups[i]()
		}
	}
	if cancel != nil {
		defer cancel()
	}

	ticker := tickerFactory()
	defer ticker.Stop()

	var streamedStderr strings.Builder
	wroteDone := false
	linesCh := lines
	doneCh := done

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
			payload, err := json.Marshal(dto.StreamEvent{Stream: line.Stream, Line: line.Text})
			if err != nil {
				if cancel != nil {
					cancel()
				}
				go drainStreamLines(linesCh)
				writeStreamDoneFallback(w, "internal error: failed to encode stream event")
				return
			}
			if err := writeStreamPayload(w, payload); err != nil {
				if cancel != nil {
					cancel()
				}
				go drainStreamLines(linesCh)
				return
			}
		case result, ok := <-resultCh:
			if !ok {
				doneCh = nil
				continue
			}
			writeStreamDoneEvent(w, result, streamedStderr.String())
			wroteDone = true
			return
		case <-ticker.Chan():
			payload, err := json.Marshal(dto.StreamEvent{Heartbeat: true})
			if err != nil {
				if cancel != nil {
					cancel()
				}
				go drainStreamLines(linesCh)
				writeStreamDoneFallback(w, "internal error: failed to encode heartbeat event")
				return
			}
			if err := writeStreamPayload(w, payload); err != nil {
				if cancel != nil {
					cancel()
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
		Done:         true,
		ReturnCode:   &returnCode,
		TimedOut:     result.TimedOut,
		Cancelled:    result.Cancelled,
		HTTPRequests: result.HTTPRequests,
		DurationMS:   result.Duration.Milliseconds(),
		Execution: dto.ExecutionMetadata{
			Tool:            result.Tool,
			ToolVersion:     result.ToolVersion,
			ArgvRedacted:    result.ArgvRedacted,
			StartedAt:       result.StartedAt,
			TimeoutMS:       result.Timeout.Milliseconds(),
			Profile:         result.Policy.Profile,
			MaxRequests:     result.Policy.MaxRequests,
			RateLimit:       result.Policy.RateLimit,
			Concurrency:     result.Policy.Concurrency,
			HealthURL:       result.Policy.HealthURL,
			Max5xxResponses: result.Policy.Max5xxResponses,
		},
		Target:            result.Target,
		SPABaseline:       result.SPABaseline,
		FalsePositiveRisk: result.FalsePositiveRisk,
		Warnings:          result.Warnings,
	}
	if terminalErr := terminalStreamError(result, streamedStderr); terminalErr != "" {
		doneEvent.Error = terminalErr
		doneEvent.Failure = &dto.FailureInfo{
			Code:      result.FailureCode,
			Message:   terminalErr,
			Retryable: result.TimedOut || result.Cancelled,
		}
	} else if result.FailureCode != "" {
		doneEvent.Failure = &dto.FailureInfo{
			Code:      result.FailureCode,
			Message:   result.FailureCode,
			Retryable: result.TimedOut || result.Cancelled,
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
