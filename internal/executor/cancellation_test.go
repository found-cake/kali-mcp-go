package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunShell_preserves_output_flushed_during_graceful_timeout(t *testing.T) {
	// Given: a process that flushes one final line when interrupted.
	command := "trap 'printf graceful-output\\n; exit 0' INT; while :; do :; done"

	// When: its execution deadline expires.
	result := RunShell(context.Background(), 20*time.Millisecond, command)

	// Then: the timeout remains explicit and the final partial output is retained.
	if !result.TimedOut || !strings.Contains(result.Stdout, "graceful-output") || !result.ProcessStarted || result.GracefulStop != time.Second {
		t.Fatalf("graceful timeout output was lost: %+v", result)
	}
}
