package main

import (
	"errors"
	"testing"
)

func TestTargetSchedulerRejectsConcurrentHeavyScanForSameTarget(t *testing.T) {
	// Given: one heavy scan already owns the full per-target budget.
	scheduler := newTargetScheduler(6, 3)
	release, err := scheduler.acquire("http://target:3000", 3)
	if err != nil {
		t.Fatalf("acquire first scan: %v", err)
	}
	defer release()

	// When: another heavy scan targets the same endpoint.
	_, err = scheduler.acquire("http://target:3000", 3)

	// Then: the second scan is rejected without affecting other targets.
	if !errors.Is(err, errTargetCapacityExceeded) {
		t.Fatalf("expected target capacity error, got %v", err)
	}
	otherRelease, err := scheduler.acquire("http://other:3000", 3)
	if err != nil {
		t.Fatalf("expected a different target to proceed: %v", err)
	}
	otherRelease()
}

func TestFiveXXCircuitBreakerCancelsAtConfiguredThreshold(t *testing.T) {
	// Given: a stream containing two observable 5xx responses.
	lines := make(chan streamStatus, 2)
	lines <- streamStatus{Code: 500}
	lines <- streamStatus{Code: 503}
	close(lines)
	cancelled := false

	// When: the circuit breaker observes the configured threshold.
	tripped := observeFiveXXResponses(lines, 2, func() { cancelled = true })

	// Then: the execution is cancelled and the breaker reports a trip.
	if !tripped || !cancelled {
		t.Fatalf("expected 5xx circuit breaker to trip: tripped=%t cancelled=%t", tripped, cancelled)
	}
}
