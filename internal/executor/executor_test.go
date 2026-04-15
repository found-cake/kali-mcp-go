package executor

import (
	"context"
	"os"
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
	case <-time.After(2 * time.Second):
		t.Fatal("expected canceled stream to finish promptly")
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
