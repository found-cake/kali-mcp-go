package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
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
	result.CallID = callIDFromContext(c)
	lifetime, err := targeting.Lifetime(request.ValidForSeconds)
	if err != nil {
		return badRequest(c, err.Error())
	}
	now := time.Now().UTC()
	if err := targeting.AttachResolution(apiTokenFromContext(c), result, now.Add(lifetime)); err != nil {
		return internalServerError(c, err.Error())
	}
	if result.RecommendationBasis == "" {
		result.RecommendationBasis = "explicit_selection_required"
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
	if _, err := targeting.Lifetime(request.ValidForSeconds); err != nil {
		return err
	}
	return nil
}
