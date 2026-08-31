package results

import (
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestToToolResultPreservesExecutionSemantics(t *testing.T) {
	startedAt := time.Date(2026, time.August, 31, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		input       executor.Result
		execution   dto.ExecutionStatus
		status      dto.RunStatus
		partial     bool
		failure     bool
		retryable   bool
		failureText string
	}{
		{
			name: "success", input: executor.Result{ReturnCode: 0, Stdout: "ok", StartedAt: startedAt, Duration: 1250 * time.Millisecond, Timeout: 30 * time.Second},
			execution: dto.ExecutionSucceeded, status: dto.RunCompleted,
		},
		{
			name: "nonzero exit", input: executor.Result{ReturnCode: 2, Stderr: " denied \n", FailureCode: "exit_nonzero", StartedAt: startedAt, Duration: time.Second, Timeout: 30 * time.Second},
			execution: dto.ExecutionFailed, status: dto.RunFailed, failure: true, failureText: "denied",
		},
		{
			name: "timeout with output", input: executor.Result{ReturnCode: -1, Stdout: "partial", TimedOut: true, FailureCode: "timeout", StartedAt: startedAt, Duration: 30 * time.Second, Timeout: 30 * time.Second},
			execution: dto.ExecutionTimedOut, status: dto.RunTimeout, partial: true, failure: true, retryable: true,
		},
		{
			name: "cancelled", input: executor.Result{ReturnCode: -1, Cancelled: true, FailureCode: "cancelled", StartedAt: startedAt, Duration: 500 * time.Millisecond, Timeout: 30 * time.Second},
			execution: dto.ExecutionCancelled, status: dto.RunCancelled, failure: true, retryable: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: an executor result in one terminal state.
			// When: it crosses the public result boundary.
			got := ToToolResult(&test.input)

			// Then: status precedence, partial output, failure metadata, and timing stay stable.
			if got.ExecutionStatus != test.execution || got.Status != test.status || got.PartialResults != test.partial {
				t.Fatalf("unexpected result state: %+v", got)
			}
			if (got.Failure != nil) != test.failure {
				t.Fatalf("unexpected failure presence: %+v", got.Failure)
			}
			if got.Failure != nil && (got.Failure.Retryable != test.retryable || got.Failure.Message != test.failureText) {
				t.Fatalf("unexpected failure metadata: %+v", got.Failure)
			}
			if got.StdoutBytes != len(test.input.Stdout) || got.StderrBytes != len(test.input.Stderr) || got.DurationMS != test.input.Duration.Milliseconds() {
				t.Fatalf("unexpected byte or duration metadata: %+v", got)
			}
			if !got.Execution.EndedAt.Equal(test.input.StartedAt.Add(test.input.Duration)) {
				t.Fatalf("unexpected end time: %s", got.Execution.EndedAt)
			}
		})
	}
}
