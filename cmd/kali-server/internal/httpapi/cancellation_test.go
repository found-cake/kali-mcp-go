package httpapi

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestHandleCancelCallCancelsRegisteredExecution(t *testing.T) {
	registry := NewCallCancellationRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	id := "call_0123456789abcdef0123456789abcdef"
	unregister := registry.Register(id, cancel)
	t.Cleanup(unregister)
	app := fiber.New()
	app.Use(CallCancellationRegistryMiddleware(registry))
	app.Post("/calls/:id/cancel", HandleCancelCall)

	response, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/calls/"+id+"/cancel", nil))
	if err != nil {
		t.Fatalf("cancel request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != fiber.StatusAccepted {
		t.Fatalf("cancel status=%d", response.StatusCode)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("registered execution was not cancelled")
	}
}

func TestHandleCancelCallRejectsUnknownAndMalformedIdentifiers(t *testing.T) {
	registry := NewCallCancellationRegistry()
	app := fiber.New()
	app.Use(CallCancellationRegistryMiddleware(registry))
	app.Post("/calls/:id/cancel", HandleCancelCall)

	for _, test := range []struct {
		id     string
		status int
	}{
		{id: "malformed", status: fiber.StatusBadRequest},
		{id: "call_0123456789abcdef0123456789abcdef", status: fiber.StatusNotFound},
	} {
		response, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/calls/"+test.id+"/cancel", nil))
		if err != nil {
			t.Fatalf("cancel %s: %v", test.id, err)
		}
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("cancel %s status=%d want=%d", test.id, response.StatusCode, test.status)
		}
	}
}
