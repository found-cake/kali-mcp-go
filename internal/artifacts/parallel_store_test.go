package artifacts

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStoreConcurrentReadsDuringExpiry(t *testing.T) {
	store := newExpiryTestStore(t)
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	stable, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, SourceCallID: "stable", Payload: []byte("retained")}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("expired")}, now)
	if err != nil {
		t.Fatal(err)
	}
	for caller := range 32 {
		t.Run(fmt.Sprint(caller), func(t *testing.T) {
			t.Parallel()
			for range 16 {
				page, err := store.ReadPage(dto.ArtifactReadRequest{ArtifactID: stable.ID}, expiring.ExpiresAt)
				if err != nil || page.Content != "retained" || page.SourceCallID != "stable" {
					t.Fatalf("stable page changed during expiry: page=%+v err=%v", page, err)
				}
				if _, _, err := store.Read(expiring.ID, expiring.ExpiresAt); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expired artifact returned: %v", err)
				}
			}
		})
	}
}

func BenchmarkStoreLookupParallel(b *testing.B) {
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	store, ids := metadataBenchmarkStore(now)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(worker *testing.PB) {
		index := 0
		for worker.Next() {
			id := ids[index]
			artifact, err := store.lookup(id, now)
			if err != nil || artifact.reference.ID != id {
				b.Errorf("lookup identity mismatch: %v", err)
				return
			}
			index = (index + 1) % len(ids)
		}
	})
}

func BenchmarkStoreMetadataMixedParallel(b *testing.B) {
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	store, ids := metadataBenchmarkStore(now)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(worker *testing.PB) {
		index := 0
		for worker.Next() {
			id := ids[index]
			if index%8 == 0 {
				store.prune(now)
				store.mu.Lock()
				artifact := store.items[id]
				store.items[id] = artifact
				store.mu.Unlock()
			} else if artifact, err := store.lookup(id, now); err != nil || artifact.reference.ID != id {
				b.Errorf("lookup identity mismatch: %v", err)
				return
			}
			index = (index + 1) % len(ids)
		}
	})
}

func metadataBenchmarkStore(now time.Time) (*Store, []string) {
	store := &Store{items: make(map[string]storedArtifact, 10_000)}
	ids := make([]string, 10_000)
	for index := range ids {
		id := fmt.Sprint(index)
		ids[index] = id
		store.items[id] = storedArtifact{reference: dto.ArtifactRef{ID: id, ExpiresAt: now.Add(time.Hour)}}
	}
	store.prune(now)
	return store, ids
}

func BenchmarkStoreReadPageParallel(b *testing.B) {
	store, err := New()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := store.Close(); err != nil {
			b.Error(err)
		}
	})
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	content := strings.Repeat("record\n", 4096)
	reference, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte(content)}, now)
	if err != nil {
		b.Fatal(err)
	}
	request := dto.ArtifactReadRequest{ArtifactID: reference.ID, Limit: defaultPageSize}
	want := content[:defaultPageSize]
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(worker *testing.PB) {
		for worker.Next() {
			page, err := store.ReadPage(request, now)
			if err != nil || page.Content != want {
				b.Errorf("page mismatch: %v", err)
				return
			}
		}
	})
}
