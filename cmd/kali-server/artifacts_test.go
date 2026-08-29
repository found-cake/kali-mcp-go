package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestArtifactStorePersistsPrivateResultAndExpiresIt(t *testing.T) {
	// Given: an isolated result artifact store.
	store, err := newArtifactStore()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.August, 29, 10, 0, 0, 0, time.UTC)

	// When: a completed tool result is saved.
	reference, err := store.save(&executor.Result{Tool: "nmap", Stdout: "scan output", ReturnCode: 0}, now)
	if err != nil {
		t.Fatalf("save result: %v", err)
	}
	artifact := store.items[reference.ID]
	info, err := os.Stat(artifact.path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}

	// Then: the file is private and becomes unavailable after its TTL.
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode = %o, want 600", info.Mode().Perm())
	}
	if _, err := store.read(reference.ID, now.Add(artifactTTL+time.Second)); !errors.Is(err, errArtifactNotFound) {
		t.Fatalf("read expired artifact: %v", err)
	}
}

func TestArtifactStoreReadsBoundedUTF8Page(t *testing.T) {
	// Given: an artifact containing multi-byte output larger than one page.
	store, err := newArtifactStore()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	reference, err := store.save(&executor.Result{Tool: "nuclei", Stdout: strings.Repeat("한글", 500)}, now)
	if err != nil {
		t.Fatalf("save result: %v", err)
	}

	// When: the first bounded page is read.
	page, err := store.readPage(dto.ArtifactReadRequest{ArtifactID: reference.ID, Limit: 256}, now)
	if err != nil {
		t.Fatalf("read page: %v", err)
	}

	// Then: it is valid UTF-8 and advertises the next byte offset.
	if !utf8.ValidString(page.Content) || !page.HasMore || page.NextOffset <= 0 || page.TotalBytes <= int64(len(page.Content)) {
		t.Fatalf("unexpected artifact page: %+v", page)
	}
}
