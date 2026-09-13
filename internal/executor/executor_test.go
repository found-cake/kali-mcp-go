package executor

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func countOpenFDs(t *testing.T) int {
	t.Helper()

	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("counting open file descriptors is unavailable: %v", err)
	}
	return len(entries)
}

func TestRunReportsScannerError(t *testing.T) {
	t.Parallel()

	res := RunShell(context.Background(), 10*time.Second, "yes a | head -c 2200000 | tr -d '\\n'")
	if res == nil {
		t.Fatal("expected result, got nil")
	}
	if res.TimedOut {
		t.Fatal("expected non-timeout result")
	}
	if res.ReturnCode == 0 {
		t.Fatalf("expected non-zero return code on scanner failure, got %d", res.ReturnCode)
	}
	if !strings.Contains(res.Stderr, "stdout scan:") {
		t.Fatalf("expected stdout scan error in stderr, got %q", res.Stderr)
	}
	if res.StdoutBytes != 1_100_000 || !res.StdoutTruncated {
		t.Fatalf("scanner failure lost output accounting: bytes=%d truncated=%t", res.StdoutBytes, res.StdoutTruncated)
	}
}

func TestRunShellBoundsRetainedOutput(t *testing.T) {
	// Given: a successful command that emits more output than one result may retain.
	command := "yes 0123456789abcdef | head -c 17000000"

	// When: the command runs through the production executor.
	result := RunShell(context.Background(), 10*time.Second, command)

	// Then: execution succeeds while retained memory is bounded and the original size is reported.
	if result.ReturnCode != 0 || result.TimedOut {
		t.Fatalf("large-output command failed: %+v", result)
	}
	if len(result.Stdout) > maximumRetainedOutputBytes || result.StdoutBytes <= len(result.Stdout) || !result.StdoutTruncated {
		t.Fatalf("output was not bounded: retained=%d observed=%d truncated=%t", len(result.Stdout), result.StdoutBytes, result.StdoutTruncated)
	}
}

func TestRunShellCountsUnterminatedOutputBytes(t *testing.T) {
	// Given: a command whose final output line has no newline terminator.
	command := "printf x"

	// When: the command runs through the production executor.
	result := RunShell(context.Background(), 10*time.Second, command)

	// Then: byte metadata reports the byte emitted by the process, not a normalized separator.
	if result.ReturnCode != 0 || result.Stdout != "x\n" || result.StdoutBytes != 1 {
		t.Fatalf("unterminated output metadata is inaccurate: %+v", result)
	}
}

func TestStreamReportsScannerError(t *testing.T) {
	t.Parallel()

	lines, done := StreamShell(context.Background(), 10*time.Second, "yes a | head -c 2200000 | tr -d '\\n'")
	for range lines {
	}

	res, ok := <-done
	if !ok {
		t.Fatal("expected done result before channel close")
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.TimedOut {
		t.Fatal("expected non-timeout result")
	}
	if res.ReturnCode == 0 {
		t.Fatalf("expected non-zero return code on scanner failure, got %d", res.ReturnCode)
	}
	if !strings.Contains(res.Stderr, "stdout scan:") {
		t.Fatalf("expected stdout scan error in stderr, got %q", res.Stderr)
	}
	if res.StdoutBytes != 1_100_000 || !res.StdoutTruncated {
		t.Fatalf("stream scanner failure lost output accounting: bytes=%d truncated=%t", res.StdoutBytes, res.StdoutTruncated)
	}
}

func TestStreamDeliversDoneAfterLineDrain(t *testing.T) {
	t.Parallel()

	lines, done := StreamShell(context.Background(), 5*time.Second, "printf 'ok\\n'")

	lineCount := 0
	for range lines {
		lineCount++
	}
	if lineCount != 1 {
		t.Fatalf("expected exactly one streamed line, got %d", lineCount)
	}

	res, ok := <-done
	if !ok {
		t.Fatal("expected done result before channel close")
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected return code 0, got %d", res.ReturnCode)
	}
	if res.Progress == nil || res.Progress.Phase != "completed" || res.Progress.ObservedOutputItems != 1 || res.Progress.LastObservedOutput != "ok" {
		t.Fatalf("unexpected final progress: %+v", res.Progress)
	}
}

func TestStreamExecDeliversDoneAfterLineDrain(t *testing.T) {
	t.Parallel()

	lines, done := StreamExec(context.Background(), 5*time.Second, "printf", "ok\n")

	lineCount := 0
	for range lines {
		lineCount++
	}
	if lineCount == 0 {
		t.Fatal("expected at least one streamed line")
	}

	res, ok := <-done
	if !ok {
		t.Fatal("expected done result before channel close")
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected return code 0, got %d", res.ReturnCode)
	}
}

func TestStreamShellStopsPromptlyAfterCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	lines, done := StreamShell(ctx, 10*time.Second, "sleep 5")
	cancel()

	for range lines {
	}

	select {
	case res := <-done:
		if res == nil {
			t.Fatal("expected non-nil result")
		}
		if !res.Cancelled || res.TimedOut {
			t.Fatalf("expected cancellation without timeout, got %+v", res)
		}
		if res.Duration <= 0 || res.StartedAt.IsZero() {
			t.Fatalf("expected execution timing metadata, got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected canceled stream to finish promptly")
	}
}

func TestRunTimeoutDoesNotReportExpectedPipeClosureAsOutputFailure(t *testing.T) {
	// Given: a quiet process that exceeds its execution budget.

	// When: the executor terminates the process and closes its output pipes.
	result := RunShell(context.Background(), 20*time.Millisecond, "sleep 1")

	// Then: only the timeout is reported, without synthetic pipe read errors.
	if !result.TimedOut {
		t.Fatalf("expected timeout, got %+v", result)
	}
	if strings.Contains(result.Stderr, "scan:") {
		t.Fatalf("unexpected pipe closure error: %q", result.Stderr)
	}
	if result.Progress == nil || result.Progress.Phase != "timed_out" || result.Progress.ResumeSupported {
		t.Fatalf("unexpected timeout progress: %+v", result.Progress)
	}
}

func TestStreamExecSupportsConcurrentSessions(t *testing.T) {
	t.Parallel()

	const sessions = 8
	var wg sync.WaitGroup
	wg.Add(sessions)

	for range sessions {
		go func() {
			defer wg.Done()
			lines, done := StreamExec(context.Background(), 5*time.Second, "printf", "ok\n")
			count := 0
			for range lines {
				count++
			}
			if count == 0 {
				t.Error("expected at least one streamed line")
				return
			}
			res := <-done
			if res == nil {
				t.Error("expected non-nil result")
				return
			}
			if res.ReturnCode != 0 {
				t.Errorf("expected return code 0, got %d", res.ReturnCode)
			}
		}()
	}

	wg.Wait()
}

func TestStreamExecDoneChannelIsBuffered(t *testing.T) {
	t.Parallel()

	_, done := StreamExec(context.Background(), 5*time.Second, "printf", "ok\n")
	if cap(done) != 1 {
		t.Fatalf("expected buffered done channel with capacity 1, got %d", cap(done))
	}
}

func TestRedactArgsHidesBrowserEvidencePath(t *testing.T) {
	// Given: a browser invocation containing its private screenshot handoff path.
	args := []string{"--url", "https://example.com", "--screenshot-path", "/tmp/private-evidence.jpg"}

	// When: reproducibility metadata is prepared for the MCP result.
	redacted := redactArgs("browser-check", args)

	// Then: the ephemeral host path is not exposed to callers.
	if strings.Contains(strings.Join(redacted, " "), "/tmp/private-evidence.jpg") {
		t.Fatalf("ephemeral path remains in argv metadata: %v", redacted)
	}
}

func TestRedactArgsHidesBrowserInputPaths(t *testing.T) {
	args := []string{
		"--url", "https://example.com",
		"--headers-file", "/tmp/private-headers.json",
		"--local-storage-file", "/tmp/private-storage.json",
	}

	redacted := redactArgs("browser-check", args)

	joined := strings.Join(redacted, " ")
	if strings.Contains(joined, "/tmp/private-headers.json") || strings.Contains(joined, "/tmp/private-storage.json") {
		t.Fatalf("ephemeral browser input path remains in argv metadata: %v", redacted)
	}
}

func TestRedactArgsHidesInlineNucleiHeaders(t *testing.T) {
	// Given: safe Nuclei arguments containing sensitive inline header values.
	args := []string{
		"-H=Authorization: Bearer private-token",
		"--header=Cookie: session=private-cookie",
		"-header=Authorization: Bearer alternate-token",
	}

	// When: reproducibility metadata is prepared for the MCP result.
	redacted := redactArgs("nuclei", args)

	// Then: flag names remain useful while their values are removed.
	want := []string{"-H=[REDACTED]", "--header=[REDACTED]", "-header=[REDACTED]"}
	if !slices.Equal(redacted, want) {
		t.Fatalf("inline header values remain in argv metadata\nwant: %v\n got: %v", want, redacted)
	}
}

func TestRunExecDoesNotLeakPipesWhenStartFails(t *testing.T) {
	baseline := countOpenFDs(t)

	for range 64 {
		res := RunExec(context.Background(), time.Second, "/definitely/missing-binary")
		if res == nil {
			t.Fatal("expected result, got nil")
		}
		if res.ReturnCode != -1 {
			t.Fatalf("expected start failure return code -1, got %d", res.ReturnCode)
		}
	}

	after := countOpenFDs(t)
	if delta := after - baseline; delta > 8 {
		t.Fatalf("expected start failures not to leak file descriptors, baseline=%d after=%d delta=%d", baseline, after, delta)
	}
}
