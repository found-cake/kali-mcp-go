package streaming

import (
	"sync/atomic"
	"testing"

	"github.com/found-cake/kali-mcp-go/internal/executor"
)

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

func TestMonitorFiveXXResponsesPassesLinesAndCancelsOnce(t *testing.T) {
	// Given: three output lines containing two target 5xx responses.
	lines := make(chan executor.Line, 3)
	lines <- executor.Line{Text: `{"status":500}`}
	lines <- executor.Line{Text: `{"status_code":200}`}
	lines <- executor.Line{Text: `{"status_code":503}`}
	close(lines)
	var cancellations atomic.Int32

	// When: the monitored stream reaches its configured threshold.
	output, tripped := MonitorFiveXXResponses(lines, 2, func() { cancellations.Add(1) })
	observed := 0
	for range output {
		observed++
	}

	// Then: every line passes through and cancellation occurs exactly once.
	if observed != 3 || !tripped.Load() || cancellations.Load() != 1 {
		t.Fatalf("unexpected breaker state: lines=%d tripped=%t cancellations=%d", observed, tripped.Load(), cancellations.Load())
	}
}
