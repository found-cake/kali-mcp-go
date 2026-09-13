package httpapi

import (
	"sync"

	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/gofiber/fiber/v3"
)

const DefaultMaxConcurrentExecutions = 10

type executionLease struct {
	release  func()
	retained bool
}

const executionLeaseKey = "execution-lease"

func NewExecutionLimiter(maxConcurrent int) *admission.Limiter {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentExecutions
	}
	return admission.NewLimiter(maxConcurrent)
}

func WithExecutionLimit(limiter *admission.Limiter, next fiber.Handler) fiber.Handler {
	if limiter == nil {
		return next
	}

	return func(c fiber.Ctx) error {
		if !limiter.TryAcquire() {
			return ServiceUnavailable(c, "server busy: too many concurrent executions")
		}

		lease := &executionLease{release: limiter.Release}
		c.Locals(executionLeaseKey, lease)
		defer func() {
			if !lease.retained {
				lease.release()
			}
		}()

		return next(c)
	}
}

func RetainExecutionLease(c fiber.Ctx) func() {
	lease, ok := c.Locals(executionLeaseKey).(*executionLease)
	if !ok || lease == nil || lease.retained {
		return nil
	}

	lease.retained = true
	var once sync.Once
	return func() {
		once.Do(lease.release)
	}
}
