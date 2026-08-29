package main

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleResolveTarget(c fiber.Ctx) error {
	request, err := parseRequest(c, validateResolveTargetRequest)
	if err != nil {
		return badRequest(c, err.Error())
	}
	result, err := tools.ResolveTarget(c.Context(), request)
	if err != nil {
		return badRequest(c, err.Error())
	}
	return c.JSON(result)
}

func validateResolveTargetRequest(request dto.ResolveTargetRequest) error {
	if strings.TrimSpace(request.Target) == "" {
		return fmt.Errorf("target is required")
	}
	if request.ConnectTimeoutMilliseconds < 0 || request.ConnectTimeoutMilliseconds > 5000 {
		return fmt.Errorf("connect_timeout_milliseconds must be between 1 and 5000")
	}
	return nil
}
