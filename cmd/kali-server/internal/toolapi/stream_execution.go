package toolapi

import (
	"context"
	"sync/atomic"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/jobs"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/streaming"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

type streamExecution struct {
	plan           *scanExecutionPlan
	beforeAnnotate func(*executor.Result)
	cleanups       []func()
}

func executeStreamPlan(c fiber.Ctx, plan *scanExecutionPlan) error {
	return executeToolStream(c, streamExecution{plan: plan})
}

func executeToolStream(c fiber.Ctx, execution streamExecution) error {
	if execution.plan.async {
		return executeAsyncTool(c, execution)
	}
	return executeSynchronousTool(c, execution)
}

func executeSynchronousTool(c fiber.Ctx, execution streamExecution) error {
	if execution.plan.dryRun {
		result := executeOrPreview(c.Context(), execution.plan)
		execution.finish(result)
		lines := make(chan executor.Line)
		close(lines)
		done := make(chan *executor.Result, 1)
		done <- result
		close(done)
		return httpapi.SendToolStream(c, lines, done, func() {}, execution.cleanupFunctions(c)...)
	}
	lines, done, cancel := execution.start(c.Context())
	return httpapi.SendToolStream(c, lines, done, cancel, execution.cleanupFunctions(c)...)
}

func executeAsyncTool(c fiber.Ctx, execution streamExecution) error {
	store := httpapi.JobStore(c)
	if store == nil {
		execution.cleanup()
		return httpapi.InternalServerError(c, "job store unavailable")
	}
	cleanups := execution.cleanupFunctions(c)
	callID := httpapi.CallID(c)
	created, err := store.Start(jobs.StartSpec{
		CallID: callID, Tool: execution.plan.args[0], Timeout: execution.plan.timeout,
		Run: func(ctx context.Context, report jobs.ProgressReporter) dto.ToolResult {
			defer runCleanups(cleanups)
			execution.plan.context = ctx
			lines, done, cancel := execution.start(ctx)
			defer cancel()
			progress := dto.ProgressMetadata{Phase: dto.ProgressRunning}
			for line := range lines {
				if line.Sequence > progress.ObservedOutputItems {
					progress.ObservedOutputItems = line.Sequence
				}
				progress.LastObservedOutput = line.Text
				report(progress)
			}
			result, ok := <-done
			if !ok || result == nil {
				return results.ToToolResult(&executor.Result{
					CallID: callID, ReturnCode: -1, FailureCode: "stream_ended_without_result",
				})
			}
			return results.ToToolResult(result)
		},
	})
	if err != nil {
		runCleanups(cleanups)
		return httpapi.InternalServerError(c, err.Error())
	}
	response, err := created.Response()
	if err != nil {
		_, _ = store.Cancel(created.ID)
		return httpapi.InternalServerError(c, err.Error())
	}
	return c.Status(fiber.StatusAccepted).JSON(response)
}

func (execution streamExecution) start(ctx context.Context) (<-chan executor.Line, <-chan *executor.Result, context.CancelFunc) {
	execCtx, cancel := context.WithCancel(ctx)
	lines, done := executor.StreamExec(execCtx, execution.plan.timeout, execution.plan.args[0], execution.plan.args[1:]...)
	lines = results.ProtectStream(execCtx, lines, execution.plan.request)
	var breakerTripped *atomic.Bool
	if execution.plan.options.Max5xxResponses > 0 {
		lines, breakerTripped = streaming.MonitorFiveXXResponses(lines, execution.plan.options.Max5xxResponses, cancel)
	}
	done = annotateResult(done, func(result *executor.Result) {
		if breakerTripped != nil && breakerTripped.Load() {
			result.Cancelled = true
			result.FailureCode = "target_5xx_threshold"
			result.Warnings = append(result.Warnings, "scan cancelled after target 5xx threshold")
		}
		execution.finish(result)
	})
	return lines, done, cancel
}

func (execution streamExecution) finish(result *executor.Result) {
	if execution.beforeAnnotate != nil {
		execution.beforeAnnotate(result)
	}
	execution.plan.annotate(result)
}

func (execution streamExecution) cleanupFunctions(c fiber.Ctx) []func() {
	cleanups := []func(){httpapi.RetainExecutionLease(c), execution.plan.release}
	return append(cleanups, execution.cleanups...)
}

func (execution streamExecution) cleanup() {
	runCleanups(append([]func(){execution.plan.release}, execution.cleanups...))
}

func runCleanups(cleanups []func()) {
	for _, cleanup := range cleanups {
		if cleanup != nil {
			cleanup()
		}
	}
}
