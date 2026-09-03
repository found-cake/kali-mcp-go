package httpapi

import (
	"fmt"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func BadRequest(c fiber.Ctx, message string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": message})
}

func InternalServerError(c fiber.Ctx, message string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": message})
}

func ServiceUnavailable(c fiber.Ctx, message string) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": message})
}

func Conflict(c fiber.Ctx, message string) error {
	return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": message})
}

func ParseRequest[T any](c fiber.Ctx, validate func(T) error) (T, error) {
	var request T
	if err := c.Bind().Body(&request); err != nil {
		return request, fmt.Errorf("invalid request body")
	}
	if err := tools.ValidateRequestSecrets(request); err != nil {
		return request, err
	}
	resolved, err := targeting.ApplyContext(APIToken(c), request, time.Now().UTC())
	if err != nil {
		return request, err
	}
	if err := validate(resolved); err != nil {
		return request, err
	}
	return resolved, nil
}
