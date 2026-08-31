package httpapi

import (
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/gofiber/fiber/v3"
)

func WriteToolResult(c fiber.Ctx, result *executor.Result, request any) error {
	results.Protect(ArtifactStore(c), result, request)
	return c.JSON(results.ToToolResult(result))
}
