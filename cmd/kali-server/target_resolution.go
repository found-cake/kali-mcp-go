package main

import (
	"fmt"
	"strings"
	"time"

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
	lifetime, err := resolutionLifetime(request.ValidForSeconds)
	if err != nil {
		return badRequest(c, err.Error())
	}
	now := time.Now().UTC()
	receipt, err := issueResolutionReceiptUntil(apiTokenFromContext(c), *result, now.Add(lifetime))
	if err != nil {
		return internalServerError(c, err.Error())
	}
	result.ResolutionID = receipt.ID
	result.ResolutionReceipt = receipt.Token
	result.ReceiptExpiresAt = receipt.ExpiresAt
	if err := attachTargetContexts(apiTokenFromContext(c), result, receipt); err != nil {
		return internalServerError(c, err.Error())
	}
	result.RecommendationBasis = "explicit_selection_required"
	if result.RecommendedTarget != "" {
		result.RecommendationBasis = "only_reachable_candidate"
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
	if _, err := resolutionLifetime(request.ValidForSeconds); err != nil {
		return err
	}
	return nil
}

func resolutionLifetime(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return resolutionReceiptLifetime, nil
	}
	lifetime := time.Duration(seconds) * time.Second
	if lifetime < time.Second || lifetime > maximumResolutionLifetime {
		return 0, fmt.Errorf("valid_for_seconds must be between 1 and 3600")
	}
	return lifetime, nil
}
