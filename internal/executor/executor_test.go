package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

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
