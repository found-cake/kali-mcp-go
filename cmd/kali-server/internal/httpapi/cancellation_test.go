package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestHandleCancelCallCancelsRegisteredExecution(t *testing.T) {
	registry := NewCallCancellationRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	id := "call_0123456789abcdef0123456789abcdef"
	unregister, err := registry.Register(id, cancel)
	if err != nil {
		t.Fatalf("register cancellation: %v", err)
	}
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

func TestCallCancellationRegistryRejectsDuplicateActiveIdentifier(t *testing.T) {
	registry := NewCallCancellationRegistry()
	firstContext, cancelFirst := context.WithCancel(context.Background())
	secondContext, cancelSecond := context.WithCancel(context.Background())
	id := "call_0123456789abcdef0123456789abcdef"
	unregister, err := registry.Register(id, cancelFirst)
	if err != nil {
		t.Fatalf("register first cancellation: %v", err)
	}
	t.Cleanup(unregister)
	if _, err := registry.Register(id, cancelSecond); !errors.Is(err, ErrCallIDAlreadyActive) {
		t.Fatalf("duplicate registration error=%v", err)
	}
	if !registry.Cancel(id) {
		t.Fatal("original registration was lost")
	}
	select {
	case <-firstContext.Done():
	default:
		t.Fatal("original call was not cancelled")
	}
	select {
	case <-secondContext.Done():
		t.Fatal("duplicate call replaced the original registration")
	default:
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
