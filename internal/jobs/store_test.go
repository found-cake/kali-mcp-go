package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type fakeTimer struct {
	mu      sync.Mutex
	stopped bool
	fire    func()
}

func (t *fakeTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}

func (t *fakeTimer) Fire() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	fire := t.fire
	t.mu.Unlock()
	fire()
}

type fakeClock struct {
	now       time.Time
	scheduled chan *fakeTimer
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) AfterFunc(_ time.Duration, fire func()) timer {
	t := &fakeTimer{fire: fire}
	c.scheduled <- t
	return t
}

func TestStoreRetainsCompletedResultForConfiguredTTL(t *testing.T) {
	// Given: an asynchronous task held until the test releases it.
	clock := &fakeClock{now: time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC), scheduled: make(chan *fakeTimer, 1)}
	store := newStore(t.Context(), 30*time.Second, clock)
	release := make(chan struct{})
	started := make(chan struct{})
	created, err := store.Start(StartSpec{
		CallID: "call_test", Tool: "nuclei_scan", Timeout: time.Minute,
		Run: func(_ context.Context, report ProgressReporter) dto.ToolResult {
			close(started)
			report(dto.ProgressMetadata{Phase: dto.ProgressRunning, ObservedOutputItems: 3})
			<-release
			return dto.ToolResult{CallID: "call_test", ExecutionStatus: dto.ExecutionSucceeded, ReturnCode: 0}
		},
	})
	if err != nil {
		t.Fatalf("start job: %v", err)
	}
	defer store.Close()
	<-started

	// When: the running job is inspected and then completes.
	pending, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("get pending job: %v", err)
	}
	close(release)
	expiry := <-clock.scheduled
	completed, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("get completed job: %v", err)
	}

	// Then: pending progress and the direct terminal ToolResult data remain available until expiry.
	if pending.Status != dto.JobPending || pending.Progress == nil || pending.Progress.ObservedOutputItems != 3 {
		t.Fatalf("unexpected pending snapshot: %+v", pending)
	}
	response, err := completed.Response()
	if err != nil {
		t.Fatalf("encode completed response: %v", err)
	}
	if response.Status != dto.JobCompleted {
		t.Fatalf("completed status=%q", response.Status)
	}
	var result dto.ToolResult
	if err := json.Unmarshal(response.Data, &result); err != nil {
		t.Fatalf("decode direct result data: %v", err)
	}
	if result.CallID != "call_test" || result.ReturnCode != 0 {
		t.Fatalf("unexpected completed data: %+v", result)
	}
	expiry.Fire()
	if _, err := store.Get(created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired job error=%v, want ErrNotFound", err)
	}
}

func TestStoreCancellationPreservesTerminalPartialResult(t *testing.T) {
	// Given: a task that reports a partial result when its job context is cancelled.
	clock := &fakeClock{now: time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC), scheduled: make(chan *fakeTimer, 1)}
	store := newStore(t.Context(), 30*time.Second, clock)
	started := make(chan struct{})
	created, err := store.Start(StartSpec{
		CallID: "call_cancel", Tool: "nikto_scan", Timeout: time.Minute,
		Run: func(ctx context.Context, _ ProgressReporter) dto.ToolResult {
			close(started)
			<-ctx.Done()
			return dto.ToolResult{
				CallID: "call_cancel", ExecutionStatus: dto.ExecutionCancelled,
				Cancelled: true, PartialResults: true, Stdout: "partial\n", ReturnCode: -1,
			}
		},
	})
	if err != nil {
		t.Fatalf("start job: %v", err)
	}
	defer store.Close()
	<-started

	// When: cancellation is requested and the task reaches its terminal state.
	cancelling, err := store.Cancel(created.ID)
	if err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	<-clock.scheduled
	terminal, err := store.Get(created.ID)
	if err != nil {
		t.Fatalf("get cancelled job: %v", err)
	}

	// Then: cancellation is visible while pending and terminal evidence is returned as error data.
	if !cancelling.CancellationRequested || terminal.Status != dto.JobError || terminal.Result == nil {
		t.Fatalf("unexpected cancellation lifecycle: cancelling=%+v terminal=%+v", cancelling, terminal)
	}
	if !terminal.Result.Cancelled || !terminal.Result.PartialResults || terminal.Result.Stdout != "partial\n" {
		t.Fatalf("cancelled result lost evidence: %+v", terminal.Result)
	}
}
