package httpapi

import (
	"context"
	"errors"
	"sync"

	"github.com/found-cake/kali-mcp-go/internal/callid"
	"github.com/gofiber/fiber/v3"
)

const callCancellationRegistryLocalKey = "call-cancellation-registry"

var ErrCallIDAlreadyActive = errors.New("call ID is already active")

type CallCancellationRegistry struct {
	active sync.Map
}

type callCancellation struct {
	cancel context.CancelFunc
}

func NewCallCancellationRegistry() *CallCancellationRegistry {
	return &CallCancellationRegistry{}
}

func (registry *CallCancellationRegistry) Register(id string, cancel context.CancelFunc) (func(), error) {
	if registry == nil || cancel == nil || !callid.Valid(id) {
		return nil, nil
	}
	entry := &callCancellation{cancel: cancel}
	if _, loaded := registry.active.LoadOrStore(id, entry); loaded {
		return nil, ErrCallIDAlreadyActive
	}
	return func() {
		registry.active.CompareAndDelete(id, entry)
	}, nil
}

func (registry *CallCancellationRegistry) Cancel(id string) bool {
	value, found := registry.active.Load(id)
	if !found {
		return false
	}
	entry, ok := value.(*callCancellation)
	if !ok {
		return false
	}
	entry.cancel()
	return true
}

func CallCancellationRegistryMiddleware(registry *CallCancellationRegistry) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(callCancellationRegistryLocalKey, registry)
		return c.Next()
	}
}

func RegisterCallCancellation(c fiber.Ctx, cancel context.CancelFunc) (func(), error) {
	registry, _ := c.Locals(callCancellationRegistryLocalKey).(*CallCancellationRegistry)
	return registry.Register(CallID(c), cancel)
}

func HandleCancelCall(c fiber.Ctx) error {
	id := c.Params("id")
	if !callid.Valid(id) {
		return BadRequest(c, "invalid call ID")
	}
	registry, _ := c.Locals(callCancellationRegistryLocalKey).(*CallCancellationRegistry)
	if registry == nil || !registry.Cancel(id) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"cancelled": false, "call_id": id})
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"cancelled": true, "call_id": id})
}
