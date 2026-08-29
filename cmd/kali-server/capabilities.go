package main

import (
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func handleScanCapabilities(c fiber.Ctx) error {
	result := tools.ScanCapabilities()
	result.CallID = callIDFromContext(c)
	return c.JSON(result)
}
