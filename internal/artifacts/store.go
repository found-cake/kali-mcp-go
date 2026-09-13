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
	ErrClosed      = errors.New("artifact store closed")
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

type timer interface {
	Stop() bool
}

type clock interface {
	AfterFunc(time.Duration, func()) timer
}

type realClock struct{}

func (realClock) AfterFunc(delay time.Duration, fire func()) timer {
	return time.AfterFunc(delay, fire)
}

type storedArtifact struct {
	path        string
	reference   dto.ArtifactRef
	expiryTimer timer
}

type Store struct {
	lifecycle  sync.RWMutex
	closed     bool
	mu         sync.RWMutex
	directory  string
	items      map[string]storedArtifact
	nextExpiry time.Time
	clock      clock
}

func New() (*Store, error) {
	return newStore(realClock{})
}

func newStore(clock clock) (*Store, error) {
	directory, err := os.MkdirTemp("", "kali-mcp-artifacts-*")
	if err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("secure artifact directory: %w", err)
	}
	return &Store{directory: directory, items: make(map[string]storedArtifact), clock: clock}, nil
}

func (s *Store) Save(content Content, now time.Time) (dto.ArtifactRef, error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return dto.ArtifactRef{}, ErrClosed
	}
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
	artifact := storedArtifact{path: path, reference: reference}
	artifact.expiryTimer = s.clock.AfterFunc(artifactTTL, func() { s.expire(id) })
	s.items[id] = artifact
	if s.nextExpiry.IsZero() || reference.ExpiresAt.Before(s.nextExpiry) {
		s.nextExpiry = reference.ExpiresAt
	}
	s.mu.Unlock()
	return reference, nil
}

func (s *Store) Read(id string, now time.Time) (dto.ArtifactRef, []byte, error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return dto.ArtifactRef{}, nil, ErrNotFound
	}
	return s.read(id, now)
}

func (s *Store) read(id string, now time.Time) (dto.ArtifactRef, []byte, error) {
	artifact, err := s.lookup(id, now)
	if err != nil {
		return dto.ArtifactRef{}, nil, ErrNotFound
	}
	payload, err := os.ReadFile(artifact.path)
	if err != nil {
		s.forget(id)
		return dto.ArtifactRef{}, nil, ErrNotFound
	}
	return artifact.reference, payload, nil
}

func (s *Store) lookup(id string, now time.Time) (storedArtifact, error) {
	s.mu.RLock()
	if !now.Before(s.nextExpiry) {
		s.mu.RUnlock()
		s.prune(now)
		s.mu.RLock()
	}
	artifact, ok := s.items[id]
	s.mu.RUnlock()
	if !ok {
		return storedArtifact{}, ErrNotFound
	}
	return artifact, nil
}

func (s *Store) forget(id string) {
	s.mu.Lock()
	artifact, found := s.items[id]
	delete(s.items, id)
	s.mu.Unlock()
	if found && artifact.expiryTimer != nil {
		artifact.expiryTimer.Stop()
	}
}

func (s *Store) Close() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.mu.Lock()
	timers := make([]timer, 0, len(s.items))
	for _, artifact := range s.items {
		if artifact.expiryTimer != nil {
			timers = append(timers, artifact.expiryTimer)
		}
	}
	s.items = make(map[string]storedArtifact)
	s.nextExpiry = time.Time{}
	s.mu.Unlock()
	for _, timer := range timers {
		timer.Stop()
	}
	return os.RemoveAll(s.directory)
}

func (s *Store) expire(id string) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.closed {
		return
	}
	s.mu.Lock()
	artifact, found := s.items[id]
	if found {
		delete(s.items, id)
		if !s.nextExpiry.Before(artifact.reference.ExpiresAt) {
			s.recomputeNextExpiryLocked()
		}
	}
	s.mu.Unlock()
	if found {
		_ = os.Remove(artifact.path)
	}
}

func (s *Store) prune(now time.Time) {
	s.mu.Lock()
	if now.Before(s.nextExpiry) {
		s.mu.Unlock()
		return
	}
	s.nextExpiry = time.Time{}
	var expired []storedArtifact
	for id, artifact := range s.items {
		if now.Before(artifact.reference.ExpiresAt) {
			if s.nextExpiry.IsZero() || artifact.reference.ExpiresAt.Before(s.nextExpiry) {
				s.nextExpiry = artifact.reference.ExpiresAt
			}
			continue
		}
		expired = append(expired, artifact)
		delete(s.items, id)
	}
	s.mu.Unlock()
	for _, artifact := range expired {
		if artifact.expiryTimer != nil {
			artifact.expiryTimer.Stop()
		}
		_ = os.Remove(artifact.path)
	}
}

func (s *Store) recomputeNextExpiryLocked() {
	s.nextExpiry = time.Time{}
	for _, artifact := range s.items {
		if s.nextExpiry.IsZero() || artifact.reference.ExpiresAt.Before(s.nextExpiry) {
			s.nextExpiry = artifact.reference.ExpiresAt
		}
	}
}

func randomID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate artifact ID: %w", err)
	}
	return "artifact_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
