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
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	artifactTTL           = time.Hour
	artifactExpiryWarning = 5 * time.Minute
	defaultPageSize       = 16 * 1024
	minimumPageSize       = 256
	maximumPageSize       = 64 * 1024
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

func (s *Store) ReadPage(request dto.ArtifactReadRequest, now time.Time) (dto.ArtifactReadResult, error) {
	reference, payload, err := s.Read(request.ArtifactID, now)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	limit, err := pageSize(request.Limit)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	total := int64(len(payload))
	if request.Offset < 0 || request.Offset > total {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	if reference.Encoding == dto.ArtifactEncodingUTF8 && request.Offset < total && !utf8.RuneStart(payload[request.Offset]) {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	end := min(request.Offset+int64(limit), total)
	if reference.Encoding == dto.ArtifactEncodingUTF8 {
		for end < total && end > request.Offset && !utf8.RuneStart(payload[end]) {
			end--
		}
	}
	content := string(payload[request.Offset:end])
	if reference.Encoding == dto.ArtifactEncodingBase64 {
		content = base64.StdEncoding.EncodeToString(payload[request.Offset:end])
	}
	expiresIn := max(int64(reference.ExpiresAt.Sub(now)/time.Second), 0)
	return dto.ArtifactReadResult{
		ArtifactID: request.ArtifactID, Content: content, Offset: request.Offset, NextOffset: end,
		HasMore: end < total, TotalBytes: total, ExpiresAt: reference.ExpiresAt,
		ExpiresInSeconds: expiresIn, ExpiringSoon: expiresIn <= int64(artifactExpiryWarning/time.Second),
		SourceCallID: reference.SourceCallID, MediaType: reference.MediaType,
		Encoding: reference.Encoding, RedactionState: reference.RedactionState, Relation: reference.Relation,
	}, nil
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

func pageSize(requested int) (int, error) {
	if requested == 0 {
		return defaultPageSize, nil
	}
	if requested < minimumPageSize || requested > maximumPageSize {
		return 0, ErrInvalidPage
	}
	return requested, nil
}

func randomID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate artifact ID: %w", err)
	}
	return "artifact_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
