package artifacts

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStoreExpiryPreservesOutOfOrderTimestamps(t *testing.T) {
	store := newExpiryTestStore(t)
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	content := Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("retained")}
	later, err := store.Save(content, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := store.Save(content, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Read(earlier.ID, earlier.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("artifact expired early: %v", err)
	}
	if _, _, err := store.Read(earlier.ID, earlier.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("artifact available at expiry: %v", err)
	}
	if _, payload, err := store.Read(later.ID, earlier.ExpiresAt); err != nil || string(payload) != "retained" {
		t.Fatalf("later artifact lost: err=%v payload=%q", err, payload)
	}
	if _, _, err := store.Read(later.ID, later.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("later artifact available at expiry: %v", err)
	}
}

func TestStoreConcurrentSaveAndRead(t *testing.T) {
	store := newExpiryTestStore(t)
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	for index := range 16 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			t.Parallel()
			payload := fmt.Append(nil, index)
			reference, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: payload}, now)
			if err != nil {
				t.Fatal(err)
			}
			_, got, err := store.Read(reference.ID, now)
			if err != nil || string(got) != string(payload) {
				t.Fatalf("read=%q want=%q err=%v", got, payload, err)
			}
		})
	}
}

func TestStoreExpiryAfterForgettingEarliest(t *testing.T) {
	store := newExpiryTestStore(t)
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	content := Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("retained")}
	earlier, err := store.Save(content, now)
	if err != nil {
		t.Fatal(err)
	}
	later, err := store.Save(content, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	store.forget(earlier.ID)
	if _, payload, err := store.Read(later.ID, earlier.ExpiresAt); err != nil || string(payload) != "retained" {
		t.Fatalf("remaining artifact lost: err=%v payload=%q", err, payload)
	}
	if _, _, err := store.Read(later.ID, later.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remaining artifact lifetime extended: %v", err)
	}
}

func newExpiryTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close artifact store: %v", err)
		}
	})
	return store
}

func BenchmarkStoreLookup(b *testing.B) {
	for _, size := range []int{100, 10_000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
			store := &Store{items: make(map[string]storedArtifact, size)}
			for index := range size {
				id := fmt.Sprint(index)
				store.items[id] = storedArtifact{reference: dto.ArtifactRef{ID: id, ExpiresAt: now.Add(time.Hour)}}
			}
			store.prune(now)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := store.lookup("0", now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
