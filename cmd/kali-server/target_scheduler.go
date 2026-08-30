package main

import (
	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/gofiber/fiber/v3"
)

const targetSchedulerLocalKey = "target-scheduler"

func targetSchedulerMiddleware(scheduler *admission.Scheduler) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(targetSchedulerLocalKey, scheduler)
		return c.Next()
	}
}

func schedulerFromContext(c fiber.Ctx) *admission.Scheduler {
	scheduler, _ := c.Locals(targetSchedulerLocalKey).(*admission.Scheduler)
	return scheduler
}

func scanWeight(tool string) int {
	switch tool {
	case "nuclei", "nikto", "sqlmap", "ffuf", "feroxbuster", "dalfox":
		return 3
	case "gobuster", "dirb", "wpscan", "hydra", "browser-check":
		return 2
	default:
		return 1
	}
}
