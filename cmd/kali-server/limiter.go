package main

import (
	"sync"

	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/gofiber/fiber/v3"
)

const defaultMaxConcurrentExecutions = 10

type executionLease struct {
	release  func()
	retained bool
}

const executionLeaseKey = "execution-lease"

func newExecutionLimiter(maxConcurrent int) *admission.Limiter {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentExecutions
	}
	return admission.NewLimiter(maxConcurrent)
}

func withExecutionLimit(limiter *admission.Limiter, next fiber.Handler) fiber.Handler {
	if limiter == nil {
		return next
	}

	return func(c fiber.Ctx) error {
		if !limiter.TryAcquire() {
			return serviceUnavailable(c, "server busy: too many concurrent executions")
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

func retainExecutionLease(c fiber.Ctx) func() {
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
