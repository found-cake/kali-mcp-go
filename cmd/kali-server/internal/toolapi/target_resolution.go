package toolapi

import (
	"fmt"
	"strings"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleResolveTarget(c fiber.Ctx) error {
	request, err := httpapi.ParseRequest(c, validateResolveTargetRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	result, err := tools.ResolveTarget(c.Context(), request)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	result.CallID = httpapi.CallID(c)
	lifetime, err := targeting.Lifetime(request.ValidForSeconds)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	now := time.Now().UTC()
	if err := targeting.AttachResolution(httpapi.APIToken(c), result, now.Add(lifetime)); err != nil {
		return httpapi.InternalServerError(c, err.Error())
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
