package httpapi

import (
	"bufio"
	"context"
	"io"
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

func TestSendToolStreamFlushesAnInitialFrame(t *testing.T) {
	// Given: an SSE tool that produces no output before a long disconnect-probe interval.
	app := fiber.New()
	lines := make(chan executor.Line)
	close(lines)
	done := make(chan *executor.Result, 1)
	app.Get("/stream", func(c fiber.Ctx) error {
		return sendToolStream(c, lines, done, func() {}, 2*time.Second)
	})
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
	client := &http.Client{Timeout: 500 * time.Millisecond}

	// When: a client opens the quiet stream.
	response, err := client.Get("http://" + listener.Addr().String() + "/stream")
	if err != nil {
		t.Fatalf("open quiet stream before the probe interval: %v", err)
	}
	defer response.Body.Close()

	// Then: headers and an initial SSE frame are available immediately.
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read initial frame: %v", err)
	}
	if line != ":\n" {
		t.Fatalf("unexpected initial frame: %q", line)
	}
	done <- &executor.Result{}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatalf("read terminal frame: %v", err)
	}
}
