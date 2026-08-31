package main

import (
	"fmt"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func toolStatus(lookup func(string) bool) map[string]bool {
	runtimeTools := tools.RuntimeToolNames()
	status := make(map[string]bool, len(runtimeTools))
	dirWordlistReady := tools.WordlistExists(tools.DefaultDirWordlistPath())
	johnWordlistReady := tools.WordlistExists(tools.DefaultJohnWordlistPath())

	for _, toolName := range runtimeTools {
		ready := lookup(toolName)
		switch toolName {
		case "gobuster", "dirb":
			ready = ready && dirWordlistReady
		case "john":
			ready = ready && johnWordlistReady
		}
		status[toolName] = ready
	}

	return status
}

func allEssentialToolsAvailable(status map[string]bool) bool {
	for _, toolName := range tools.EssentialRuntimeToolNames() {
		if !status[toolName] {
			return false
		}
	}
	return true
}

func badRequest(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
}

func internalServerError(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": msg})
}

func serviceUnavailable(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": msg})
}

func bindJSON(c fiber.Ctx, dst any) error {
	return c.Bind().Body(dst)
}

func parseRequest[T any](c fiber.Ctx, validate func(T) error) (T, error) {
	var req T
	bindErr := bindJSON(c, &req)
	if bindErr != nil {
		return req, fmt.Errorf("invalid request body")
	}
	if err := tools.ValidateRequestSecrets(req); err != nil {
		return req, err
	}
	resolved, err := targeting.ApplyContext(apiTokenFromContext(c), req, time.Now().UTC())
	if err != nil {
		return req, err
	}
	req = resolved
	if err := validate(req); err != nil {
		return req, err
	}
	return req, nil
}
