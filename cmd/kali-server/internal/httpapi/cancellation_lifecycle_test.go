package httpapi

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestWithCallCancellationCoversWorkBeforeStreamStarts(t *testing.T) {
	app := fiber.New()
	registry := NewCallCancellationRegistry()
	app.Use(CallTelemetryMiddleware(nil))
	app.Use(CallCancellationRegistryMiddleware(registry))
	app.Use(BearerAuthMiddleware("test-secret"))
	started := make(chan struct{})
	app.Get("/prepare", WithCallCancellation(func(c fiber.Ctx) error {
		close(started)
		<-c.Context().Done()
		return BadRequest(c, c.Context().Err().Error())
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
	prepareRequest, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/prepare", nil)
	if err != nil {
		t.Fatalf("create prepare request: %v", err)
	}
	prepareRequest.Header.Set(fiber.HeaderAuthorization, "Bearer test-secret")
	prepareRequest.Header.Set(dto.CallIDHeader, callID)
	prepareDone := make(chan *http.Response, 1)
	prepareFailed := make(chan error, 1)
	go func() {
		response, requestErr := http.DefaultClient.Do(prepareRequest)
		if requestErr != nil {
			prepareFailed <- requestErr
			return
		}
		prepareDone <- response
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("pre-stream work did not start")
	}

	cancelRequest, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/calls/"+callID+"/cancel", nil)
	if err != nil {
		t.Fatalf("create cancel request: %v", err)
	}
	cancelRequest.Header.Set(fiber.HeaderAuthorization, "Bearer test-secret")
	cancelResponse, err := http.DefaultClient.Do(cancelRequest)
	if err != nil {
		t.Fatalf("cancel pre-stream work: %v", err)
	}
	cancelResponse.Body.Close()
	if cancelResponse.StatusCode != fiber.StatusAccepted {
		t.Fatalf("cancel status=%d want=%d", cancelResponse.StatusCode, fiber.StatusAccepted)
	}
	select {
	case response := <-prepareDone:
		response.Body.Close()
		if response.StatusCode != fiber.StatusBadRequest {
			t.Fatalf("cancelled preparation status=%d", response.StatusCode)
		}
	case err := <-prepareFailed:
		t.Fatalf("preparation request failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("pre-stream work did not observe call cancellation")
	}
}
