package main

import (
	"errors"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestAuthSessionStoreReturnsMaskedMetadataAndExpiresSecrets(t *testing.T) {
	// Given: a target authentication context with sensitive headers and cookies.
	now := time.Date(2026, time.August, 29, 10, 0, 0, 0, time.UTC)
	store := newAuthSessionStore()
	request := dto.AuthSessionCreateRequest{
		Label:      "customer-session-1",
		Origin:     "https://example.com",
		Headers:    map[string]string{"Authorization": "Bearer secret"},
		Cookie:     "session=secret-cookie",
		TTLSeconds: 60,
	}

	// When: the session is created and later read after its TTL.
	metadata, err := store.create(request, now)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	_, expiredErr := store.get(metadata.SessionID, now.Add(61*time.Second))

	// Then: metadata exposes only header names and the expired secret is unavailable.
	if len(metadata.HeaderNames) != 1 || metadata.HeaderNames[0] != "Authorization" || !metadata.HasCookie {
		t.Fatalf("unexpected masked metadata: %+v", metadata)
	}
	if errors.Is(expiredErr, errAuthSessionExpired) == false {
		t.Fatalf("expected expired session, got %v", expiredErr)
	}
}

func TestApplyAuthSessionRejectsDifferentTargetOrigin(t *testing.T) {
	// Given: a session bound to one target origin.
	session := authSession{origin: "https://example.com", headers: map[string]string{"Authorization": "Bearer secret"}}

	// When: a scan for another origin attempts to reuse it.
	_, err := applyAuthSession([]string{"ffuf", "-u", "https://other.example/FUZZ"}, "https://other.example/FUZZ", session)

	// Then: cross-origin credential reuse is rejected.
	if !errors.Is(err, errAuthSessionOriginMismatch) {
		t.Fatalf("expected origin mismatch, got %v", err)
	}
}
