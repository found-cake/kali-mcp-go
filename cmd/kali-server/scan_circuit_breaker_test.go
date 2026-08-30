package main

import "testing"

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
