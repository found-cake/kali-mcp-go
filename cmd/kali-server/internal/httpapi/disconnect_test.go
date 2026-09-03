package httpapi

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
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

func TestExplicitCallCancellationReturnsTerminalStreamEvent(t *testing.T) {
	app := fiber.New()
	registry := NewCallCancellationRegistry()
	app.Use(CallTelemetryMiddleware(nil))
	app.Use(CallCancellationRegistryMiddleware(registry))
	app.Post("/stream", WithCallCancellation(func(c fiber.Ctx) error {
		lines := make(chan executor.Line)
		done := make(chan *executor.Result, 1)
		executionContext, cancel := context.WithCancel(c.Context())
		go func() {
			<-executionContext.Done()
			time.Sleep(50 * time.Millisecond)
			close(lines)
			done <- &executor.Result{ReturnCode: -1, Cancelled: true}
			close(done)
		}()
		return SendToolStream(c, lines, done, cancel)
	}))
	app.Post("/calls/:id/cancel", HandleCancelCall)
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
	callID := "call_0123456789abcdef0123456789abcdef"
	request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/stream", nil)
	if err != nil {
		t.Fatalf("create stream request: %v", err)
	}
	request.Header.Set(dto.CallIDHeader, callID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer response.Body.Close()
	cancelRequest, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/calls/"+callID+"/cancel", nil)
	if err != nil {
		t.Fatalf("create cancel request: %v", err)
	}
	cancelResponse, err := http.DefaultClient.Do(cancelRequest)
	if err != nil {
		t.Fatalf("cancel stream: %v", err)
	}
	cancelResponse.Body.Close()
	if cancelResponse.StatusCode != fiber.StatusAccepted {
		t.Fatalf("cancel status=%d", cancelResponse.StatusCode)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read cancelled stream: %v", err)
	}
	if !strings.Contains(string(payload), `"done":true`) || !strings.Contains(string(payload), `"cancelled":true`) {
		t.Fatalf("cancelled stream lacks terminal result: %q", payload)
	}
}
