package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleCreateAuthSession(c fiber.Ctx) error {
	request, err := parseRequest(c, validateAuthSessionCreateRequest)
	if err != nil {
		return badRequest(c, err.Error())
	}
	store := authSessionStoreFromContext(c)
	metadata, err := store.create(request, time.Now().UTC())
	if err != nil {
		return badRequest(c, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(metadata)
}

func handleListAuthSessions(c fiber.Ctx) error {
	store := authSessionStoreFromContext(c)
	return c.JSON(dto.AuthSessionListResult{Sessions: store.list(time.Now().UTC())})
}

func handleDeleteAuthSession(c fiber.Ctx) error {
	id := strings.TrimSpace(c.Params("id"))
	if id == "" {
		return badRequest(c, "session ID is required")
	}
	store := authSessionStoreFromContext(c)
	if !store.delete(id) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": errAuthSessionNotFound.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func validateAuthSessionCreateRequest(request dto.AuthSessionCreateRequest) error {
	if strings.TrimSpace(request.Label) == "" {
		return fmt.Errorf("label is required")
	}
	if request.TTLSeconds < 0 {
		return fmt.Errorf("ttl_seconds must be positive")
	}
	for _, tool := range request.AllowedTools {
		if !isSessionCapableTool(tool) {
			return fmt.Errorf("unsupported allowed tool %q", tool)
		}
	}
	return nil
}

func isSessionCapableTool(tool string) bool {
	switch tool {
	case "ffuf", "nuclei", "feroxbuster", "gobuster", "sqlmap", "dalfox", "whatweb", "browser-check":
		return true
	default:
		return false
	}
}
