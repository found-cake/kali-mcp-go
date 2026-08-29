package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const (
	authSessionStoreLocalKey = "auth-session-store"
	defaultSessionTTL        = 15 * time.Minute
	maximumSessionTTL        = time.Hour
)

var (
	errAuthSessionNotFound       = errors.New("authentication session not found")
	errAuthSessionExpired        = errors.New("authentication session expired")
	errAuthSessionOriginMismatch = errors.New("authentication session origin does not match target")
)

type authSession struct {
	metadata dto.AuthSessionMetadata
	origin   string
	headers  map[string]string
	cookie   string
}

type authSessionStore struct {
	mu       sync.Mutex
	sessions map[string]authSession
}

func newAuthSessionStore() *authSessionStore {
	return &authSessionStore{sessions: make(map[string]authSession)}
}

func (s *authSessionStore) create(request dto.AuthSessionCreateRequest, now time.Time) (dto.AuthSessionMetadata, error) {
	origin, err := normalizeOrigin(request.Origin)
	if err != nil {
		return dto.AuthSessionMetadata{}, err
	}
	if err := validateSessionSecrets(request); err != nil {
		return dto.AuthSessionMetadata{}, err
	}
	ttl := defaultSessionTTL
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}
	if ttl > maximumSessionTTL {
		return dto.AuthSessionMetadata{}, fmt.Errorf("ttl_seconds must not exceed %d", int(maximumSessionTTL/time.Second))
	}
	id, err := randomSessionID()
	if err != nil {
		return dto.AuthSessionMetadata{}, err
	}
	headerNames := make([]string, 0, len(request.Headers))
	for name := range request.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	allowed := append([]string(nil), request.AllowedTools...)
	sort.Strings(allowed)
	metadata := dto.AuthSessionMetadata{
		SessionID: id, Label: request.Label, Origin: origin, ExpiresAt: now.Add(ttl),
		AllowedTools: allowed, HeaderNames: headerNames, HasCookie: request.Cookie != "",
	}
	s.mu.Lock()
	s.sessions[id] = authSession{metadata: metadata, origin: origin, headers: cloneHeaders(request.Headers), cookie: request.Cookie}
	s.mu.Unlock()
	return metadata, nil
}

func (s *authSessionStore) get(id string, now time.Time) (authSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return authSession{}, errAuthSessionNotFound
	}
	if !now.Before(session.metadata.ExpiresAt) {
		delete(s.sessions, id)
		return authSession{}, errAuthSessionExpired
	}
	return session, nil
}

func (s *authSessionStore) list(now time.Time) []dto.AuthSessionMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]dto.AuthSessionMetadata, 0, len(s.sessions))
	for id, session := range s.sessions {
		if !now.Before(session.metadata.ExpiresAt) {
			delete(s.sessions, id)
			continue
		}
		items = append(items, session.metadata)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].SessionID < items[j].SessionID })
	return items
}

func (s *authSessionStore) delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, found := s.sessions[id]
	delete(s.sessions, id)
	return found
}

func authSessionStoreMiddleware(store *authSessionStore) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Locals(authSessionStoreLocalKey, store)
		return c.Next()
	}
}

func authSessionStoreFromContext(c fiber.Ctx) *authSessionStore {
	store, _ := c.Locals(authSessionStoreLocalKey).(*authSessionStore)
	return store
}

func randomSessionID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return "auth_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func normalizeOrigin(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("origin must be an http or https origin")
	}
	if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("origin must not include credentials, path, query, or fragment")
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func validateSessionSecrets(request dto.AuthSessionCreateRequest) error {
	if len(request.Headers) == 0 && request.Cookie == "" {
		return fmt.Errorf("at least one header or cookie is required")
	}
	for name, value := range request.Headers {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name+value, "\r\n") {
			return fmt.Errorf("headers must not contain empty names or line breaks")
		}
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Cookie") {
			return fmt.Errorf("use origin for Host and cookie for Cookie")
		}
	}
	if strings.ContainsAny(request.Cookie, "\r\n") {
		return fmt.Errorf("cookie must not contain line breaks")
	}
	return nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for name, value := range headers {
		cloned[name] = value
	}
	return cloned
}
