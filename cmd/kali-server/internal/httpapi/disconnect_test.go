package httpapi

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/gofiber/fiber/v3"
)

func TestSendToolStreamReleasesExecutionLeaseAfterClientDisconnect(t *testing.T) {
	// Given: a real streaming HTTP connection holding the only execution lease.
	app := fiber.New()
	limiter := NewExecutionLimiter(1)
	cancelled := make(chan struct{})
	sendAfterDisconnect := make(chan struct{})
	app.Get("/stream", WithExecutionLimit(limiter, func(c fiber.Ctx) error {
		lines := make(chan executor.Line)
		done := make(chan *executor.Result)
		go func() {
			lines <- executor.Line{Stream: "stdout", Text: "started"}
			<-sendAfterDisconnect
			lines <- executor.Line{Stream: "stdout", Text: "after-disconnect"}
			close(lines)
		}()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-ctx.Done()
			close(cancelled)
		}()
		return sendToolStream(c, lines, done, cancel, 50*time.Millisecond, RetainExecutionLease(c))
	}))
	app.Get("/probe", WithExecutionLimit(limiter, func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- app.Listener(listener, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() {
		_ = app.Shutdown()
		<-serverDone
	})
	response, err := http.Get("http://" + listener.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read first event: %v", err)
	}

	// When: the client abandons the stream and the server writes again.
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	close(sendAfterDisconnect)

	// Then: stream cancellation runs and the execution slot becomes reusable.
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("stream cancellation was not observed after disconnect")
	}
	probe, err := http.Get("http://" + listener.Addr().String() + "/probe")
	if err != nil {
		t.Fatalf("probe released lease: %v", err)
	}
	defer probe.Body.Close()
	if probe.StatusCode != fiber.StatusOK {
		t.Fatalf("execution lease remained held: status=%d", probe.StatusCode)
	}
}
