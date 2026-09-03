//go:build unix

package executor

import (
	"context"
	"errors"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestStreamShellKillsDescendantAfterCancel(t *testing.T) {
	// Given: a shell command with a descendant that ignores graceful termination signals.
	ctx, cancel := context.WithCancel(context.Background())
	lines, done := StreamShell(ctx, 10*time.Second, `sh -c 'trap "" INT TERM; printf "%d\n" "$$"; while :; do sleep 1; done' & wait`)
	line := <-lines
	pid, err := strconv.Atoi(line.Text)
	if err != nil {
		t.Fatalf("parse descendant pid %q: %v", line.Text, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	// When: the parent execution context is cancelled.
	cancel()
	for range lines {
	}
	result := <-done

	// Then: cancellation completes and no descendant remains in the process group.
	if result == nil || !result.Cancelled {
		t.Fatalf("unexpected cancellation result: %+v", result)
	}
	if !waitForProcessExit(pid, time.Second) {
		t.Fatalf("descendant process %d survived cancellation", pid)
	}
}

func waitForProcessExit(pid int, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return false
		}
	}
}
