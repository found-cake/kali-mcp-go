package toolapi

import (
	"context"
	"sync/atomic"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/streaming"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func runTool[T any](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	return withPreparedTool(c, toolExecutionSpec[T]{validate: validate, argsFor: argsFor}, func(plan *scanExecutionPlan) error {
		defer plan.release()
		result := executeOrPreview(c.Context(), plan)
		plan.annotate(result)
		return c.JSON(results.ToToolResult(result))
	})
}

func runToolStream[T dto.TimeoutRequest](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	return withPreparedTool(c, toolExecutionSpec[T]{validate: validate, argsFor: argsFor}, func(plan *scanExecutionPlan) error {
		return executeStreamPlan(c, plan)
	})
}

type toolExecutionSpec[T any] struct {
	validate func(T) error
	argsFor  func(T) ([]string, error)
	decorate func(T, *scanExecutionPlan) error
}

func withPreparedTool[T any](c fiber.Ctx, spec toolExecutionSpec[T], execute func(*scanExecutionPlan) error) error {
	request, err := httpapi.ParseRequest(c, spec.validate)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	args, err := spec.argsFor(request)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	if len(args) == 0 {
		return httpapi.InternalServerError(c, "internal error: no command generated")
	}
	plan, err := prepareScanExecution(c, request, args)
	if err != nil {
		return scanPreparationError(c, err)
	}
	if spec.decorate != nil {
		if err := spec.decorate(request, plan); err != nil {
			plan.release()
			return scanPreparationError(c, err)
		}
	}
	return execute(plan)
}

func executeStreamPlan(c fiber.Ctx, plan *scanExecutionPlan) error {
	if plan.dryRun {
		result := executeOrPreview(c.Context(), plan)
		plan.annotate(result)
		lines := make(chan executor.Line)
		close(lines)
		done := make(chan *executor.Result, 1)
		done <- result
		close(done)
		release := httpapi.RetainExecutionLease(c)
		cancel := plan.streamCancel
		if cancel == nil {
			cancel = func() {}
		}
		if plan.cancelRegistration != nil {
			return httpapi.SendRegisteredToolStream(c, lines, done, cancel, plan.cancelRegistration, release, plan.release)
		}
		return httpapi.SendToolStream(c, lines, done, cancel, release, plan.release)
	}
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamExec(execCtx, plan.timeout, plan.args[0], plan.args[1:]...)
	lines = results.ProtectStream(execCtx, lines, plan.request)
	var breakerTripped *atomic.Bool
	if plan.options.Max5xxResponses > 0 {
		lines, breakerTripped = streaming.MonitorFiveXXResponses(lines, plan.options.Max5xxResponses, cancel)
	}
	done = annotateResult(done, func(result *executor.Result) {
		if breakerTripped != nil && breakerTripped.Load() {
			result.Cancelled = true
			result.FailureCode = "target_5xx_threshold"
			result.Warnings = append(result.Warnings, "scan cancelled after target 5xx threshold")
		}
		plan.annotate(result)
	})
	release := httpapi.RetainExecutionLease(c)
	return httpapi.SendToolStream(c, lines, done, cancel, release, plan.release)
}

func executeOrPreview(ctx context.Context, plan *scanExecutionPlan) *executor.Result {
	if plan.dryRun {
		return executor.PreviewExec(ctx, plan.timeout, plan.args[0], plan.args[1:]...)
	}
	return executor.RunExec(ctx, plan.timeout, plan.args[0], plan.args[1:]...)
}
