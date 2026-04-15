package main

import (
	"fmt"
	"sync"

	"github.com/gofiber/fiber/v3"
)

const defaultMaxConcurrentExecutions = 10

type executionLimiter struct {
	sem chan struct{}
}

type executionLease struct {
	release  func()
	retained bool
}

const executionLeaseKey = "execution-lease"

func newExecutionLimiter(maxConcurrent int) *executionLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentExecutions
	}
	return &executionLimiter{sem: make(chan struct{}, maxConcurrent)}
}

func (l *executionLimiter) tryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *executionLimiter) release() {
	if l == nil {
		return
	}
	select {
	case <-l.sem:
	default:
		panic(fmt.Sprintf("execution limiter release invariant violated: no slot to release (capacity=%d)", cap(l.sem)))
	}
}

func withExecutionLimit(limiter *executionLimiter, next fiber.Handler) fiber.Handler {
	if limiter == nil {
		return next
	}

	return func(c fiber.Ctx) error {
		if !limiter.tryAcquire() {
			return serviceUnavailable(c, "server busy: too many concurrent executions")
		}

		lease := &executionLease{release: limiter.release}
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
