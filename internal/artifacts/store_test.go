package artifacts

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStorePersistsPrivateArtifactAndPrunesExpiredFile(t *testing.T) {
	// Given: an isolated artifact store and one UTF-8 result.
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	reference, err := store.Save(Content{
		Kind: "tool-result-json", MediaType: "application/json", Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactSensitiveUnredacted, SourceCallID: "call-1",
		Relation: dto.ArtifactRelationToolResult, Payload: []byte("scan output"),
	}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}
	stored := store.items[reference.ID]

	// When: storage permissions are inspected and the artifact expires.
	directoryInfo, err := os.Stat(store.directory)
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	fileInfo, err := os.Stat(stored.path)
	if err != nil {
		t.Fatalf("stat artifact: %v", err)
	}
	_, _, readErr := store.Read(reference.ID, now.Add(artifactTTL+time.Second))

	// Then: private permissions and expiry semantics remain unchanged.
	if directoryInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected permissions: directory=%o file=%o", directoryInfo.Mode().Perm(), fileInfo.Mode().Perm())
	}
	if !errors.Is(readErr, ErrNotFound) {
		t.Fatalf("read expired artifact: %v", readErr)
	}
	if _, err := os.Stat(stored.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired artifact file remains: %v", err)
	}
}

func TestStoreReadsBoundedUTF8AndBase64Pages(t *testing.T) {
	// Given: UTF-8 text and binary artifacts.
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	textReference, err := store.Save(Content{
		Kind: "text", MediaType: "text/plain", Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactSensitiveUnredacted, Payload: []byte(strings.Repeat("한글", 500)),
	}, now)
	if err != nil {
		t.Fatalf("save text: %v", err)
	}
	binary := []byte{0x89, 0x50, 0x4e, 0x47}
	binaryReference, err := store.Save(Content{
		Kind: "binary", MediaType: "image/png", Encoding: dto.ArtifactEncodingBase64,
		RedactionState: dto.ArtifactSensitiveUnredacted, Payload: binary,
	}, now)
	if err != nil {
		t.Fatalf("save binary: %v", err)
	}

	// When: one bounded page is read from each artifact.
	textPage, err := store.ReadPage(dto.ArtifactReadRequest{ArtifactID: textReference.ID, Limit: 256}, now)
	if err != nil {
		t.Fatalf("read text page: %v", err)
	}
	binaryPage, err := store.ReadPage(dto.ArtifactReadRequest{ArtifactID: binaryReference.ID, Limit: 256}, now)
	if err != nil {
		t.Fatalf("read binary page: %v", err)
	}

	// Then: offsets stay byte-based while each representation remains valid.
	if !utf8.ValidString(textPage.Content) || !textPage.HasMore || textPage.NextOffset <= 0 || textPage.NextOffset > 256 {
		t.Fatalf("unexpected UTF-8 page: %+v", textPage)
	}
	if binaryPage.Content != base64.StdEncoding.EncodeToString(binary) || binaryPage.NextOffset != int64(len(binary)) {
		t.Fatalf("unexpected base64 page: %+v", binaryPage)
	}
}

func TestStoreRejectsInvalidPageBoundaries(t *testing.T) {
	// Given: a multi-byte UTF-8 artifact.
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	reference, err := store.Save(Content{
		Encoding: dto.ArtifactEncodingUTF8, RedactionState: dto.ArtifactSensitiveUnredacted, Payload: []byte("한글"),
	}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	// When: callers request invalid limits and offsets.
	requests := []dto.ArtifactReadRequest{
		{ArtifactID: reference.ID, Limit: 255},
		{ArtifactID: reference.ID, Limit: 65537},
		{ArtifactID: reference.ID, Offset: -1, Limit: 256},
		{ArtifactID: reference.ID, Offset: 1, Limit: 256},
		{ArtifactID: reference.ID, Offset: 7, Limit: 256},
	}

	// Then: every invalid page is rejected with the same typed error.
	for _, request := range requests {
		if _, err := store.ReadPage(request, now); !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("request %+v returned %v", request, err)
		}
	}
}

func TestStoreTreatsMissingBackingFileAsNotFound(t *testing.T) {
	// Given: a stored artifact whose private backing file disappears.
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	reference, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("evidence")}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}
	if err := os.Remove(store.items[reference.ID].path); err != nil {
		t.Fatalf("remove backing file: %v", err)
	}

	// When: the artifact is read through the store.
	_, _, readErr := store.Read(reference.ID, now)

	// Then: filesystem details do not leak through the store contract.
	if !errors.Is(readErr, ErrNotFound) {
		t.Fatalf("read missing artifact: %v", readErr)
	}
}
