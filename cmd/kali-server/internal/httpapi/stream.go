package httpapi

import (
	"bufio"
	"context"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/streaming"
	"github.com/gofiber/fiber/v3"
)

const streamHeartbeatInterval = 15 * time.Second

func SendToolStream(c fiber.Ctx, lines <-chan executor.Line, done <-chan *executor.Result, cancel context.CancelFunc, cleanups ...func()) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("X-Accel-Buffering", "no")
	config := streaming.Config{
		CallID: CallID(c), Lines: lines, Done: done, Cancel: cancel,
		HeartbeatInterval: streamHeartbeatInterval, Cleanups: cleanups,
	}
	return c.SendStreamWriter(func(writer *bufio.Writer) {
		streaming.Run(writer, config)
	})
}
