package main

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const artifactStoreLocalKey = "artifact-store"

func artifactStoreMiddleware(store *artifactstore.Store) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(artifactStoreLocalKey, store)
		return c.Next()
	}
}

func artifactStoreFromContext(c fiber.Ctx) *artifactstore.Store {
	store, _ := c.Locals(artifactStoreLocalKey).(*artifactstore.Store)
	return store
}

func attachResultArtifact(store *artifactstore.Store, result *executor.Result, state dto.ArtifactRedactionState) {
	if store == nil || result == nil {
		return
	}
	rebuildEvidenceManifest(result)
	payload, err := json.MarshalIndent(results.ToToolResult(result), "", "  ")
	if err != nil {
		result.Warnings = append(result.Warnings, "result artifact unavailable: encode artifact: "+err.Error())
		return
	}
	artifact, err := store.Save(artifactstore.Content{
		Kind: "tool-result-json", MediaType: fiber.MIMEApplicationJSON,
		Encoding: dto.ArtifactEncodingUTF8, RedactionState: state,
		SourceCallID: result.CallID, Relation: dto.ArtifactRelationToolResult, Payload: payload,
	}, time.Now().UTC())
	if err != nil {
		result.Warnings = append(result.Warnings, "result artifact unavailable: "+err.Error())
		return
	}
	result.Artifacts = append(result.Artifacts, artifact)
	rebuildEvidenceManifest(result)
}

func rebuildEvidenceManifest(result *executor.Result) {
	if result == nil || len(result.Artifacts) == 0 {
		return
	}
	manifest := &dto.EvidenceManifest{GroupID: result.CallID, Artifacts: make([]dto.EvidenceArtifact, 0, len(result.Artifacts))}
	for _, artifact := range result.Artifacts {
		manifest.Artifacts = append(manifest.Artifacts, dto.EvidenceArtifact{ID: artifact.ID, Kind: artifact.Kind, Relation: artifact.Relation})
		if artifact.Relation == dto.ArtifactRelationToolResult {
			manifest.PrimaryArtifactID = artifact.ID
		}
	}
	result.Evidence = manifest
}

func handleGetArtifact(c fiber.Ctx) error {
	reference, payload, err := artifactStoreFromContext(c).Read(c.Params("id"), time.Now().UTC())
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": artifactstore.ErrNotFound.Error()})
	}
	c.Set(fiber.HeaderContentType, reference.MediaType)
	return c.Send(payload)
}

func handleGetArtifactPage(c fiber.Ctx) error {
	offset, err := strconv.ParseInt(c.Query("offset", "0"), 10, 64)
	if err != nil {
		return badRequest(c, "offset must be an integer")
	}
	limit, err := strconv.Atoi(c.Query("limit", "0"))
	if err != nil {
		return badRequest(c, "limit must be an integer")
	}
	page, err := artifactStoreFromContext(c).ReadPage(dto.ArtifactReadRequest{
		ArtifactID: c.Params("id"),
		Offset:     offset,
		Limit:      limit,
	}, time.Now().UTC())
	if errors.Is(err, artifactstore.ErrNotFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": artifactstore.ErrNotFound.Error()})
	}
	if err != nil {
		return badRequest(c, artifactstore.ErrInvalidPage.Error())
	}
	page.CallID = callIDFromContext(c)
	return c.JSON(page)
}
