//go:build unix

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestToolVersionCancellationKillsDescendants(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "child-pid")
	executable := filepath.Join(directory, "version-probe")
	t.Cleanup(func() { versionCache.Delete(executable) })
	script := "#!/bin/sh\nsleep 30 &\nchild=$!\nprintf '%s' \"$child\" > \"$VERSION_PROBE_MARKER\"\nwait \"$child\"\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatalf("write version probe: %v", err)
	}
	t.Setenv("VERSION_PROBE_MARKER", marker)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() { done <- toolVersionWithTimeout(ctx, executable, 10*time.Second) }()

	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(marker)
		if err == nil {
			childPID, err = strconv.Atoi(string(contents))
			if err != nil {
				t.Fatalf("parse child PID: %v", err)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		t.Fatal("version probe did not start")
	}
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	cancel()
	select {
	case version := <-done:
		if version != "unknown" {
			t.Fatalf("cancelled version probe returned %q", version)
		}
	case <-time.After(2500 * time.Millisecond):
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		<-done
		t.Fatal("cancelled version probe retained a descendant process")
	}
	if !waitForProcessExit(childPID, time.Second) {
		t.Fatalf("version probe descendant %d survived cancellation", childPID)
	}

	recoveryScript := "#!/bin/sh\nprintf 'version 1.0\\n'\n"
	if err := os.WriteFile(executable, []byte(recoveryScript), 0o700); err != nil {
		t.Fatalf("replace version probe: %v", err)
	}
	if version := toolVersionWithTimeout(context.Background(), executable, 10*time.Second); version != "version 1.0" {
		t.Fatalf("version cache did not recover after cancellation: %q", version)
	}
	cachedScript := "#!/bin/sh\nprintf 'unexpected second probe\\n'\n"
	if err := os.WriteFile(executable, []byte(cachedScript), 0o700); err != nil {
		t.Fatalf("replace cached version probe: %v", err)
	}
	if version := toolVersionWithTimeout(context.Background(), executable, 10*time.Second); version != "version 1.0" {
		t.Fatalf("successful version probe was not cached: %q", version)
	}
}

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
