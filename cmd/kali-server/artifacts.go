package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const (
	artifactStoreLocalKey = "artifact-store"
	artifactTTL           = time.Hour
	defaultArtifactPage   = 16 * 1024
	minimumArtifactPage   = 256
	maximumArtifactPage   = 64 * 1024
)

var (
	errArtifactNotFound    = errors.New("artifact not found or expired")
	errInvalidArtifactPage = errors.New("invalid artifact page")
)

type storedArtifact struct {
	path      string
	expiresAt time.Time
}

type artifactStore struct {
	mu        sync.Mutex
	directory string
	items     map[string]storedArtifact
}

func newArtifactStore() (*artifactStore, error) {
	directory, err := os.MkdirTemp("", "kali-mcp-artifacts-*")
	if err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("secure artifact directory: %w", err)
	}
	return &artifactStore{directory: directory, items: make(map[string]storedArtifact)}, nil
}

func (s *artifactStore) save(result *executor.Result, now time.Time) (dto.ArtifactRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	id, err := randomArtifactID()
	if err != nil {
		return dto.ArtifactRef{}, err
	}
	expiresAt := now.Add(artifactTTL)
	path := filepath.Join(s.directory, id+".json")
	payload, err := json.MarshalIndent(toAPIResult(result), "", "  ")
	if err != nil {
		return dto.ArtifactRef{}, fmt.Errorf("encode artifact: %w", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return dto.ArtifactRef{}, fmt.Errorf("write artifact: %w", err)
	}
	s.items[id] = storedArtifact{path: path, expiresAt: expiresAt}
	return dto.ArtifactRef{ID: id, Kind: "tool-result-json", Location: "/api/artifacts/" + id, ExpiresAt: expiresAt}, nil
}

func (s *artifactStore) read(id string, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	artifact, ok := s.items[id]
	if !ok {
		return nil, errArtifactNotFound
	}
	payload, err := os.ReadFile(artifact.path)
	if err != nil {
		delete(s.items, id)
		return nil, errArtifactNotFound
	}
	return payload, nil
}

func (s *artifactStore) readPage(request dto.ArtifactReadRequest, now time.Time) (dto.ArtifactReadResult, error) {
	payload, err := s.read(request.ArtifactID, now)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	limit, err := artifactPageSize(request.Limit)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	total := int64(len(payload))
	if request.Offset < 0 || request.Offset > total {
		return dto.ArtifactReadResult{}, errInvalidArtifactPage
	}
	if request.Offset < total && !utf8.RuneStart(payload[request.Offset]) {
		return dto.ArtifactReadResult{}, errInvalidArtifactPage
	}
	end := min(request.Offset+int64(limit), total)
	for end < total && end > request.Offset && !utf8.RuneStart(payload[end]) {
		end--
	}
	return dto.ArtifactReadResult{
		ArtifactID: request.ArtifactID,
		Content:    string(payload[request.Offset:end]),
		Offset:     request.Offset,
		NextOffset: end,
		HasMore:    end < total,
		TotalBytes: total,
	}, nil
}

func artifactPageSize(requested int) (int, error) {
	if requested == 0 {
		return defaultArtifactPage, nil
	}
	if requested < minimumArtifactPage || requested > maximumArtifactPage {
		return 0, errInvalidArtifactPage
	}
	return requested, nil
}

func (s *artifactStore) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make(map[string]storedArtifact)
	return os.RemoveAll(s.directory)
}

func (s *artifactStore) pruneLocked(now time.Time) {
	for id, artifact := range s.items {
		if now.Before(artifact.expiresAt) {
			continue
		}
		_ = os.Remove(artifact.path)
		delete(s.items, id)
	}
}

func randomArtifactID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate artifact ID: %w", err)
	}
	return "artifact_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func artifactStoreMiddleware(store *artifactStore) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(artifactStoreLocalKey, store)
		return c.Next()
	}
}

func artifactStoreFromContext(c fiber.Ctx) *artifactStore {
	store, _ := c.Locals(artifactStoreLocalKey).(*artifactStore)
	return store
}

func attachResultArtifact(store *artifactStore, result *executor.Result) {
	if store == nil || result == nil {
		return
	}
	artifact, err := store.save(result, time.Now().UTC())
	if err != nil {
		result.Warnings = append(result.Warnings, "result artifact unavailable: "+err.Error())
		return
	}
	result.Artifacts = append(result.Artifacts, artifact)
}

func handleGetArtifact(c fiber.Ctx) error {
	payload, err := artifactStoreFromContext(c).read(c.Params("id"), time.Now().UTC())
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": errArtifactNotFound.Error()})
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
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
	page, err := artifactStoreFromContext(c).readPage(dto.ArtifactReadRequest{
		ArtifactID: c.Params("id"),
		Offset:     offset,
		Limit:      limit,
	}, time.Now().UTC())
	if errors.Is(err, errArtifactNotFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": errArtifactNotFound.Error()})
	}
	if err != nil {
		return badRequest(c, errInvalidArtifactPage.Error())
	}
	page.CallID = callIDFromContext(c)
	return c.JSON(page)
}
