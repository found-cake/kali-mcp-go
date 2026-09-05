package artifacts

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	artifactTTL           = time.Hour
	artifactExpiryWarning = 5 * time.Minute
)

var (
	ErrNotFound    = errors.New("artifact not found or expired")
	ErrInvalidPage = errors.New("invalid artifact page")
)

type Content struct {
	Kind           string
	MediaType      string
	Encoding       dto.ArtifactEncoding
	RedactionState dto.ArtifactRedactionState
	SourceCallID   string
	Relation       dto.ArtifactRelation
	Payload        []byte
}

type storedArtifact struct {
	path      string
	reference dto.ArtifactRef
}

type Store struct {
	mu        sync.Mutex
	directory string
	items     map[string]storedArtifact
}

func New() (*Store, error) {
	directory, err := os.MkdirTemp("", "kali-mcp-artifacts-*")
	if err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("secure artifact directory: %w", err)
	}
	return &Store{directory: directory, items: make(map[string]storedArtifact)}, nil
}

func (s *Store) Save(content Content, now time.Time) (dto.ArtifactRef, error) {
	id, err := randomID()
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

func (s *Store) Read(id string, now time.Time) (dto.ArtifactRef, []byte, error) {
	s.prune(now)
	s.mu.Lock()
	artifact, ok := s.items[id]
	s.mu.Unlock()
	if !ok {
		return dto.ArtifactRef{}, nil, ErrNotFound
	}
	payload, err := os.ReadFile(artifact.path)
	if err != nil {
		s.mu.Lock()
		delete(s.items, id)
		s.mu.Unlock()
		return dto.ArtifactRef{}, nil, ErrNotFound
	}
	return artifact.reference, payload, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	s.items = make(map[string]storedArtifact)
	s.mu.Unlock()
	return os.RemoveAll(s.directory)
}

func (s *Store) prune(now time.Time) {
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

func randomID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate artifact ID: %w", err)
	}
	return "artifact_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
