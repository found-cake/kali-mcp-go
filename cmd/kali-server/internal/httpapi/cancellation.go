package httpapi

import (
	"context"
	"errors"
	"sync"

	"github.com/found-cake/kali-mcp-go/internal/callid"
	"github.com/gofiber/fiber/v3"
)

const callCancellationRegistryLocalKey = "call-cancellation-registry"

const callCancellationLeaseLocalKey = "call-cancellation-lease"

const callTransportContextLocalKey = "call-transport-context"

var ErrCallIDAlreadyActive = errors.New("call ID is already active")

type CallCancellationRegistry struct {
	active sync.Map
}

type callCancellation struct {
	cancel context.CancelFunc
}

type callCancellationLease struct {
	cancel     context.CancelFunc
	unregister func()
	retained   bool
	once       sync.Once
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

func WithCallCancellation(next fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		transportContext := c.Context()
		c.Locals(callTransportContextLocalKey, transportContext)
		ctx, cancel := context.WithCancel(transportContext)
		c.SetContext(ctx)
		unregister, err := RegisterCallCancellation(c, cancel)
		if err != nil {
			cancel()
			return Conflict(c, err.Error())
		}
		lease := &callCancellationLease{cancel: cancel, unregister: unregister}
		c.Locals(callCancellationLeaseLocalKey, lease)
		defer func() {
			if !lease.retained {
				lease.release()
			}
		}()
		return next(c)
	}
}

func transportContext(c fiber.Ctx) context.Context {
	ctx, ok := c.Locals(callTransportContextLocalKey).(context.Context)
	if !ok || ctx == nil {
		return c.Context()
	}
	return ctx
}

func RetainCallCancellation(c fiber.Ctx) func() {
	lease, ok := c.Locals(callCancellationLeaseLocalKey).(*callCancellationLease)
	if !ok || lease == nil || lease.retained {
		return nil
	}
	lease.retained = true
	return lease.release
}

func (lease *callCancellationLease) release() {
	lease.once.Do(func() {
		lease.cancel()
		if lease.unregister != nil {
			lease.unregister()
		}
	})
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
