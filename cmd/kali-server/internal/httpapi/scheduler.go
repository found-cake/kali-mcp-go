package httpapi

import (
	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/gofiber/fiber/v3"
)

const targetSchedulerLocalKey = "target-scheduler"

func TargetSchedulerMiddleware(scheduler *admission.Scheduler) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(targetSchedulerLocalKey, scheduler)
		return c.Next()
	}
}

func Scheduler(c fiber.Ctx) *admission.Scheduler {
	scheduler, _ := c.Locals(targetSchedulerLocalKey).(*admission.Scheduler)
	return scheduler
}
