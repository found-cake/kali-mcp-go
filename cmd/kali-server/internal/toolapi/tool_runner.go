package toolapi

import (
	"context"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func runTool[T any](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	return withPreparedTool(c, toolExecutionSpec[T]{validate: validate, argsFor: argsFor}, func(plan *scanExecutionPlan) error {
		if plan.async {
			return executeAsyncTool(c, streamExecution{plan: plan})
		}
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

func executeOrPreview(ctx context.Context, plan *scanExecutionPlan) *executor.Result {
	if plan.dryRun {
		return executor.PreviewExec(ctx, plan.timeout, plan.args[0], plan.args[1:]...)
	}
	return executor.RunExec(ctx, plan.timeout, plan.args[0], plan.args[1:]...)
}
