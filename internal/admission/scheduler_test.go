package admission

import (
	"errors"
	"sync"
	"testing"
)

func TestSchedulerEnforcesGlobalAndPerTargetCapacity(t *testing.T) {
	// Given: weighted global capacity four and per-target capacity three.
	scheduler := NewScheduler(4, 3)
	releaseFirst, err := scheduler.Acquire("target-a", 3)
	if err != nil {
		t.Fatalf("acquire first target: %v", err)
	}
	defer releaseFirst()

	// When: another heavy scan targets the same service and a light scan targets another service.
	_, targetErr := scheduler.Acquire("target-a", 1)
	releaseOther, otherErr := scheduler.Acquire("target-b", 1)
	if otherErr == nil {
		defer releaseOther()
	}
	_, globalErr := scheduler.Acquire("target-c", 1)

	// Then: target and global limits remain independently identifiable.
	if !errors.Is(targetErr, ErrTargetCapacityExceeded) || otherErr != nil || !errors.Is(globalErr, ErrGlobalCapacityExceeded) {
		t.Fatalf("unexpected admission errors: target=%v other=%v global=%v", targetErr, otherErr, globalErr)
	}
}

func TestSchedulerTargetCapacityErrorReportsRejectedLease(t *testing.T) {
	// Given: one target already consuming its entire weighted capacity.
	scheduler := NewScheduler(4, 3)
	release, err := scheduler.Acquire("target-a", 3)
	if err != nil {
		t.Fatalf("acquire target capacity: %v", err)
	}
	defer release()

	// When: another lease is requested for that target.
	_, err = scheduler.Acquire("target-a", 1)

	// Then: the rejection exposes the scope and exact capacity values.
	var capacityErr *CapacityError
	if !errors.As(err, &capacityErr) {
		t.Fatalf("capacity error = %v, want *CapacityError", err)
	}
	if capacityErr.Scope() != CapacityScopeTarget || capacityErr.Used() != 3 || capacityErr.Limit() != 3 || capacityErr.RequestedWeight() != 1 {
		t.Fatalf("unexpected target capacity metadata: %+v", capacityErr)
	}
}

func TestSchedulerGlobalCapacityErrorReportsRejectedLease(t *testing.T) {
	// Given: independent targets already consuming the global weighted capacity.
	scheduler := NewScheduler(4, 3)
	releaseFirst, err := scheduler.Acquire("target-a", 3)
	if err != nil {
		t.Fatalf("acquire first target: %v", err)
	}
	defer releaseFirst()
	releaseSecond, err := scheduler.Acquire("target-b", 1)
	if err != nil {
		t.Fatalf("acquire second target: %v", err)
	}
	defer releaseSecond()

	// When: another lease would exceed the global capacity.
	_, err = scheduler.Acquire("target-c", 1)

	// Then: the rejection exposes the scope and exact capacity values.
	var capacityErr *CapacityError
	if !errors.As(err, &capacityErr) {
		t.Fatalf("capacity error = %v, want *CapacityError", err)
	}
	if capacityErr.Scope() != CapacityScopeGlobal || capacityErr.Used() != 4 || capacityErr.Limit() != 4 || capacityErr.RequestedWeight() != 1 {
		t.Fatalf("unexpected global capacity metadata: %+v", capacityErr)
	}
}

func TestSchedulerReleaseIsIdempotentAndRestoresCapacity(t *testing.T) {
	// Given: a full scheduler lease for one target.
	scheduler := NewScheduler(3, 3)
	release, err := scheduler.Acquire("target-a", 3)
	if err != nil {
		t.Fatalf("acquire target: %v", err)
	}

	// When: the lease is released twice and the same weight is acquired again.
	release()
	release()
	releaseAgain, err := scheduler.Acquire("target-a", 3)
	if err == nil {
		defer releaseAgain()
	}

	// Then: duplicate cleanup does not corrupt capacity accounting.
	if err != nil {
		t.Fatalf("acquire after duplicate release: %v", err)
	}
}

func TestSchedulerEmptyTargetUsesOnlyGlobalCapacity(t *testing.T) {
	// Given: a scheduler whose per-target capacity is lower than the requested weight.
	scheduler := NewScheduler(3, 1)

	// When: capacity is acquired without a target identity.
	release, err := scheduler.Acquire("", 3)
	if err == nil {
		defer release()
	}

	// Then: empty targets bypass per-target accounting but still consume global weight.
	if err != nil {
		t.Fatalf("empty target was rejected: %v", err)
	}
	if _, err := scheduler.Acquire("other", 1); !errors.Is(err, ErrGlobalCapacityExceeded) {
		t.Fatalf("global capacity was not consumed: %v", err)
	}
}

func TestSchedulerSupportsConcurrentAcquireAndRelease(t *testing.T) {
	// Given: a scheduler with independent capacity for eight targets.
	scheduler := NewScheduler(8, 1)
	var group sync.WaitGroup
	group.Add(8)
	errorsFound := make(chan error, 8)

	// When: each target acquires and releases its own lease concurrently.
	for index := range 8 {
		go func() {
			defer group.Done()
			release, err := scheduler.Acquire(string(rune('a'+index)), 1)
			if err != nil {
				errorsFound <- err
				return
			}
			release()
		}()
	}
	group.Wait()
	close(errorsFound)

	// Then: every independent lease completes without a capacity or race failure.
	for err := range errorsFound {
		t.Fatalf("concurrent acquisition failed: %v", err)
	}
}
