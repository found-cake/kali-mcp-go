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

func ArtifactStoreMiddleware(store *artifactstore.Store) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(artifactStoreLocalKey, store)
		return c.Next()
	}
}

func ArtifactStore(c fiber.Ctx) *artifactstore.Store {
	store, _ := c.Locals(artifactStoreLocalKey).(*artifactstore.Store)
	return store
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
	page, err := ArtifactStore(c).ReadPage(dto.ArtifactReadRequest{
		ArtifactID: c.Params("id"),
		Offset:     offset,
		Limit:      limit,
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
