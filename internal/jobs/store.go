package jobs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const DefaultRetention = 30 * time.Second

var (
	ErrNotFound = errors.New("job not found or expired")
	ErrClosed   = errors.New("job store is closed")
)

type timer interface {
	Stop() bool
}

type clock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) timer
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func (realClock) AfterFunc(delay time.Duration, fire func()) timer {
	return time.AfterFunc(delay, fire)
}

type ProgressReporter func(dto.ProgressMetadata)

type Task func(context.Context, ProgressReporter) dto.ToolResult

type StartSpec struct {
	CallID  string
	Tool    string
	Timeout time.Duration
	Run     Task
}

type Snapshot struct {
	ID                    string
	Status                dto.JobStatus
	CallID                string
	Tool                  string
	StartedAt             time.Time
	Timeout               time.Duration
	Progress              *dto.ProgressMetadata
	CancellationRequested bool
	Result                *dto.ToolResult
	ExpiresAt             time.Time
}

type record struct {
	snapshot Snapshot
	cancel   context.CancelFunc
	timer    timer
}

type Store struct {
	mu        sync.Mutex
	root      context.Context
	stop      context.CancelFunc
	retention time.Duration
	clock     clock
	jobs      map[string]*record
	wg        sync.WaitGroup
	closed    bool
}

func New(parent context.Context) *Store {
	return newStore(parent, DefaultRetention, realClock{})
}

func newStore(parent context.Context, retention time.Duration, clock clock) *Store {
	root, stop := context.WithCancel(parent)
	return &Store{
		root: root, stop: stop, retention: retention, clock: clock,
		jobs: make(map[string]*record),
	}
}

func (s *Store) Start(spec StartSpec) (Snapshot, error) {
	if spec.Run == nil {
		return Snapshot{}, fmt.Errorf("start job: task is required")
	}
	id, err := newID()
	if err != nil {
		return Snapshot{}, err
	}
	ctx, cancel := context.WithCancel(s.root)
	entry := &record{
		snapshot: Snapshot{
			ID: id, Status: dto.JobPending, CallID: spec.CallID, Tool: spec.Tool,
			StartedAt: s.clock.Now(), Timeout: spec.Timeout,
		},
		cancel: cancel,
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		return Snapshot{}, ErrClosed
	}
	s.jobs[id] = entry
	s.wg.Add(1)
	created := cloneSnapshot(entry.snapshot)
	s.mu.Unlock()
	go s.run(ctx, entry, spec.Run)
	return created, nil
}

func (s *Store) run(ctx context.Context, entry *record, task Task) {
	defer s.wg.Done()
	result := task(ctx, func(progress dto.ProgressMetadata) {
		s.report(entry.snapshot.ID, progress)
	})
	s.complete(entry.snapshot.ID, result)
}

func (s *Store) report(id string, progress dto.ProgressMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.jobs[id]
	if !found || entry.snapshot.Status != dto.JobPending {
		return
	}
	entry.snapshot.Progress = &progress
}

func (s *Store) complete(id string, result dto.ToolResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.jobs[id]
	if !found {
		return
	}
	entry.snapshot.Status = dto.JobCompleted
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		entry.snapshot.Status = dto.JobError
	}
	entry.snapshot.Result = &result
	entry.snapshot.Progress = result.Progress
	entry.snapshot.ExpiresAt = s.clock.Now().Add(s.retention)
	entry.timer = s.clock.AfterFunc(s.retention, func() { s.expire(id) })
}

func (s *Store) expire(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.jobs[id]
	if found && entry.snapshot.Status != dto.JobPending {
		delete(s.jobs, id)
	}
}

func (s *Store) Get(id string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.jobs[id]
	if !found {
		return Snapshot{}, ErrNotFound
	}
	if entry.snapshot.Status != dto.JobPending && !s.clock.Now().Before(entry.snapshot.ExpiresAt) {
		delete(s.jobs, id)
		if entry.timer != nil {
			entry.timer.Stop()
		}
		return Snapshot{}, ErrNotFound
	}
	return cloneSnapshot(entry.snapshot), nil
}

func (s *Store) Cancel(id string) (Snapshot, error) {
	s.mu.Lock()
	entry, found := s.jobs[id]
	if !found {
		s.mu.Unlock()
		return Snapshot{}, ErrNotFound
	}
	if entry.snapshot.Status != dto.JobPending {
		snapshot := cloneSnapshot(entry.snapshot)
		s.mu.Unlock()
		return snapshot, nil
	}
	entry.snapshot.CancellationRequested = true
	cancel := entry.cancel
	snapshot := cloneSnapshot(entry.snapshot)
	s.mu.Unlock()
	cancel()
	return snapshot, nil
}

func (s *Store) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	records := make([]*record, 0, len(s.jobs))
	for _, entry := range s.jobs {
		records = append(records, entry)
	}
	s.jobs = make(map[string]*record)
	s.mu.Unlock()
	s.stop()
	for _, entry := range records {
		entry.cancel()
		if entry.timer != nil {
			entry.timer.Stop()
		}
	}
	s.wg.Wait()
}

func (s Snapshot) Response() (dto.JobResponse, error) {
	var value []byte
	var err error
	switch s.Status {
	case dto.JobPending:
		value, err = json.Marshal(dto.JobPendingData{
			CallID: s.CallID, Tool: s.Tool, StartedAt: s.StartedAt, TimeoutMS: s.Timeout.Milliseconds(),
			Progress: s.Progress, CancellationRequested: s.CancellationRequested,
		})
	case dto.JobCompleted, dto.JobError:
		value, err = json.Marshal(s.Result)
	default:
		return dto.JobResponse{}, fmt.Errorf("unsupported job status %q", s.Status)
	}
	if err != nil {
		return dto.JobResponse{}, fmt.Errorf("encode job data: %w", err)
	}
	response := dto.JobResponse{JobID: s.ID, Status: s.Status, Data: value}
	if !s.ExpiresAt.IsZero() {
		expiresAt := s.ExpiresAt
		response.ExpiresAt = &expiresAt
	}
	return response, nil
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	if snapshot.Progress != nil {
		progress := *snapshot.Progress
		snapshot.Progress = &progress
	}
	if snapshot.Result != nil {
		result := *snapshot.Result
		snapshot.Result = &result
	}
	return snapshot
}

func newID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate job ID: %w", err)
	}
	return "job_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
