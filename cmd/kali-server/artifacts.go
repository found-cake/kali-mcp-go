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
	artifactExpiryWarning = 5 * time.Minute
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
	reference dto.ArtifactRef
}

type artifactContent struct {
	Kind           string
	MediaType      string
	Encoding       dto.ArtifactEncoding
	RedactionState dto.ArtifactRedactionState
	SourceCallID   string
	Relation       dto.ArtifactRelation
	Payload        []byte
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

func (s *artifactStore) save(result *executor.Result, state dto.ArtifactRedactionState, now time.Time) (dto.ArtifactRef, error) {
	payload, err := json.MarshalIndent(toAPIResult(result), "", "  ")
	if err != nil {
		return dto.ArtifactRef{}, fmt.Errorf("encode artifact: %w", err)
	}
	return s.saveContent(artifactContent{
		Kind: "tool-result-json", MediaType: fiber.MIMEApplicationJSON,
		Encoding: dto.ArtifactEncodingUTF8, RedactionState: state,
		SourceCallID: result.CallID, Relation: dto.ArtifactRelationToolResult, Payload: payload,
	}, now)
}

func (s *artifactStore) saveContent(content artifactContent, now time.Time) (dto.ArtifactRef, error) {
	id, err := randomArtifactID()
	if err != nil {
		return dto.ArtifactRef{}, err
	}
	reference := dto.ArtifactRef{
		ID: id, Kind: content.Kind, Location: "/api/artifacts/" + id, ExpiresAt: now.Add(artifactTTL),
		SourceCallID: content.SourceCallID, MediaType: content.MediaType, Encoding: content.Encoding,
		RedactionState: content.RedactionState, Relation: content.Relation,
	}
	path := filepath.Join(s.directory, id+".artifact")
	if err := os.WriteFile(path, content.Payload, 0o600); err != nil {
		return dto.ArtifactRef{}, fmt.Errorf("write artifact: %w", err)
	}
	s.prune(now)
	s.mu.Lock()
	s.items[id] = storedArtifact{path: path, reference: reference}
	s.mu.Unlock()
	return reference, nil
}

func (s *artifactStore) read(id string, now time.Time) (storedArtifact, []byte, error) {
	s.prune(now)
	s.mu.Lock()
	artifact, ok := s.items[id]
	s.mu.Unlock()
	if !ok {
		return storedArtifact{}, nil, errArtifactNotFound
	}
	payload, err := os.ReadFile(artifact.path)
	if err != nil {
		s.mu.Lock()
		delete(s.items, id)
		s.mu.Unlock()
		return storedArtifact{}, nil, errArtifactNotFound
	}
	return artifact, payload, nil
}

func (s *artifactStore) readPage(request dto.ArtifactReadRequest, now time.Time) (dto.ArtifactReadResult, error) {
	artifact, payload, err := s.read(request.ArtifactID, now)
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
	if artifact.reference.Encoding == dto.ArtifactEncodingUTF8 && request.Offset < total && !utf8.RuneStart(payload[request.Offset]) {
		return dto.ArtifactReadResult{}, errInvalidArtifactPage
	}
	end := min(request.Offset+int64(limit), total)
	if artifact.reference.Encoding == dto.ArtifactEncodingUTF8 {
		for end < total && end > request.Offset && !utf8.RuneStart(payload[end]) {
			end--
		}
	}
	content := string(payload[request.Offset:end])
	if artifact.reference.Encoding == dto.ArtifactEncodingBase64 {
		content = base64.StdEncoding.EncodeToString(payload[request.Offset:end])
	}
	expiresIn := max(int64(artifact.reference.ExpiresAt.Sub(now)/time.Second), 0)
	return dto.ArtifactReadResult{
		ArtifactID: request.ArtifactID, Content: content, Offset: request.Offset, NextOffset: end,
		HasMore: end < total, TotalBytes: total, ExpiresAt: artifact.reference.ExpiresAt,
		ExpiresInSeconds: expiresIn, ExpiringSoon: expiresIn <= int64(artifactExpiryWarning/time.Second),
		SourceCallID: artifact.reference.SourceCallID, MediaType: artifact.reference.MediaType,
		Encoding: artifact.reference.Encoding, RedactionState: artifact.reference.RedactionState,
		Relation: artifact.reference.Relation,
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
	s.items = make(map[string]storedArtifact)
	s.mu.Unlock()
	return os.RemoveAll(s.directory)
}

func (s *artifactStore) prune(now time.Time) {
	s.mu.Lock()
	var expired []string
	for id, artifact := range s.items {
		if now.Before(artifact.reference.ExpiresAt) {
			continue
		}
		expired = append(expired, artifact.path)
		delete(s.items, id)
	}
	s.mu.Unlock()
	for _, path := range expired {
		_ = os.Remove(path)
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

func attachResultArtifact(store *artifactStore, result *executor.Result, state dto.ArtifactRedactionState) {
	if store == nil || result == nil {
		return
	}
	rebuildEvidenceManifest(result)
	artifact, err := store.save(result, state, time.Now().UTC())
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
	artifact, payload, err := artifactStoreFromContext(c).read(c.Params("id"), time.Now().UTC())
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": errArtifactNotFound.Error()})
	}
	c.Set(fiber.HeaderContentType, artifact.reference.MediaType)
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
