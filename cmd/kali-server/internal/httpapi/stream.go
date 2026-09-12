package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/streaming"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/sse"
)

const (
	streamHeartbeatInterval       = 15 * time.Second
	streamDisconnectProbeInterval = 500 * time.Millisecond
)

func SendToolStream(c fiber.Ctx, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, cleanups ...func()) error {
	if release := RetainCallCancellation(c); release != nil {
		cleanups = append(cleanups, release)
		return sendToolStream(c, lines, done, cancel, streamDisconnectProbeInterval, cleanups...)
	}
	unregister, err := RegisterCallCancellation(c, cancel)
	if err != nil {
		cancelAndCleanup(cancel, cleanups)
		return Conflict(c, err.Error())
	}
	if unregister != nil {
		cleanups = append(cleanups, unregister)
	}
	return sendToolStream(c, lines, done, cancel, streamDisconnectProbeInterval, cleanups...)
}

func sendToolStream(c fiber.Ctx, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, disconnectProbeInterval time.Duration, cleanups ...func()) error {
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() { cancelAndCleanup(nil, cleanups) })
	}
	finish := func() {
		if cancel != nil {
			cancel()
		}
		cleanup()
	}
	config := streaming.Config{
		CallID: CallID(c), Lines: lines, Done: done, Cancel: cancel,
		HeartbeatInterval: streamHeartbeatInterval, Cleanups: []func(){cleanup},
	}
	handler := sse.New(sse.Config{
		HeartbeatInterval: disconnectProbeInterval,
		Handler: func(_ fiber.Ctx, stream *sse.Stream) error {
			if err := stream.Comment(""); err != nil {
				finish()
				return err
			}
			config.Context = stream.Context()
			streaming.Run(&ssePayloadWriter{stream: stream}, config)
			return stream.Err()
		},
	})
	c.SetContext(transportContext(c))
	if err := handler(c); err != nil {
		finish()
		return err
	}
	return nil
}

func cancelAndCleanup(cancel context.CancelFunc, cleanups []func()) {
	if cancel != nil {
		cancel()
	}
	for _, cleanup := range cleanups {
		if cleanup != nil {
			cleanup()
		}
	}
}

type ssePayloadWriter struct {
	stream *sse.Stream
	buffer bytes.Buffer
}

func (writer *ssePayloadWriter) WriteString(value string) (int, error) {
	return writer.buffer.WriteString(value)
}

func (writer *ssePayloadWriter) Flush() error {
	frame := writer.buffer.String()
	writer.buffer.Reset()
	if !strings.HasPrefix(frame, "data: ") || !strings.HasSuffix(frame, "\n\n") {
		return fmt.Errorf("invalid SSE data frame")
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(frame, "data: "), "\n\n")
	if !json.Valid([]byte(payload)) {
		return fmt.Errorf("invalid SSE JSON payload")
	}
	return writer.stream.Event(sse.Event{Data: json.RawMessage(payload)})
}
