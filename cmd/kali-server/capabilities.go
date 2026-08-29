package main

import (
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func handleScanCapabilities(c fiber.Ctx) error {
	return c.JSON(tools.ScanCapabilities())
}
