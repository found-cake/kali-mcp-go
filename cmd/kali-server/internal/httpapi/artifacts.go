package httpapi

import (
	"errors"
	"strconv"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const artifactStoreLocalKey = "artifact-store"

type artifactStoreLocal struct {
	store *artifactstore.Store
}

func ArtifactStoreMiddleware(store *artifactstore.Store) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(artifactStoreLocalKey, artifactStoreLocal{store: store})
		return c.Next()
	}
}

func ArtifactStore(c fiber.Ctx) *artifactstore.Store {
	local, _ := c.Locals(artifactStoreLocalKey).(artifactStoreLocal)
	return local.store
}

func HandleGetArtifact(c fiber.Ctx) error {
	reference, payload, err := ArtifactStore(c).Read(c.Params("id"), time.Now().UTC())
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": artifactstore.ErrNotFound.Error()})
	}
	c.Set(fiber.HeaderContentType, reference.MediaType)
	return c.Send(payload)
}

func HandleGetArtifactPage(c fiber.Ctx) error {
	offset, err := strconv.ParseInt(c.Query("offset", "0"), 10, 64)
	if err != nil {
		return BadRequest(c, "offset must be an integer")
	}
	limit, err := strconv.Atoi(c.Query("limit", "0"))
	if err != nil {
		return BadRequest(c, "limit must be an integer")
	}
	startLine, err := strconv.Atoi(c.Query("start_line", "0"))
	if err != nil {
		return BadRequest(c, "start_line must be an integer")
	}
	lineCount, err := strconv.Atoi(c.Query("line_count", "0"))
	if err != nil {
		return BadRequest(c, "line_count must be an integer")
	}
	page, err := ArtifactStore(c).ReadPage(dto.ArtifactReadRequest{
		ArtifactID: c.Params("id"),
		Section:    dto.ArtifactSection(c.Query("section")),
		Offset:     offset,
		Limit:      limit,
		StartLine:  startLine,
		LineCount:  lineCount,
	}, time.Now().UTC())
	if errors.Is(err, artifactstore.ErrNotFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": artifactstore.ErrNotFound.Error()})
	}
	if err != nil {
		return BadRequest(c, artifactstore.ErrInvalidPage.Error())
	}
	page.CallID = CallID(c)
	return c.JSON(page)
}
