package artifacts

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type expiryTestTimer struct {
	delay   time.Duration
	fire    func()
	stopped bool
}

func (timer *expiryTestTimer) Stop() bool {
	wasActive := !timer.stopped
	timer.stopped = true
	return wasActive
}

func (timer *expiryTestTimer) Fire() {
	if !timer.stopped {
		timer.fire()
	}
}

type expiryTestClock struct {
	scheduled chan *expiryTestTimer
}

func (clock *expiryTestClock) AfterFunc(delay time.Duration, fire func()) timer {
	timer := &expiryTestTimer{delay: delay, fire: fire}
	clock.scheduled <- timer
	return timer
}

func TestStoreRemovesExpiredFileWithoutFollowupRequest(t *testing.T) {
	// Given: an artifact store whose expiry timer is observable.
	clock := &expiryTestClock{scheduled: make(chan *expiryTestTimer, 1)}
	store, err := newStore(clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	reference, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("sensitive")}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	stored := store.items[reference.ID]
	timer := <-clock.scheduled

	// When: the one-hour retention timer fires without another store operation.
	timer.Fire()

	// Then: both metadata and the sensitive backing file are removed.
	if timer.delay != artifactTTL {
		t.Fatalf("expiry delay=%s want=%s", timer.delay, artifactTTL)
	}
	if _, found := store.items[reference.ID]; found {
		t.Fatal("expired artifact metadata remains")
	}
	if _, err := os.Stat(stored.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired artifact file remains: %v", err)
	}
}

func TestStoreRejectsSaveAfterClose(t *testing.T) {
	// Given: an artifact store whose backing directory has been closed.
	store, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// When: a caller attempts to save after shutdown.
	_, err = store.Save(Content{Payload: []byte("late")}, time.Now().UTC())

	// Then: the lifecycle error is explicit and the backing directory stays removed.
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("save after close error=%v want=%v", err, ErrClosed)
	}
	if _, statErr := os.Stat(store.directory); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("closed artifact directory was recreated: %v", statErr)
	}
}

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
