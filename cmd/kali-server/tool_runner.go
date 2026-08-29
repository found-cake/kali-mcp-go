package main

import (
	"context"
	"sync/atomic"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func runTool[T any](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	req, err := parseRequest(c, validate)
	if err != nil {
		return badRequest(c, err.Error())
	}
	args, err := argsFor(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	if len(args) == 0 {
		return internalServerError(c, "internal error: no command generated")
	}
	plan, err := prepareScanExecution(c, req, args)
	if err != nil {
		return scanPreparationError(c, err)
	}
	defer plan.release()
	result := executor.RunExec(c.Context(), plan.timeout, plan.args[0], plan.args[1:]...)
	plan.annotate(result)
	return c.JSON(toAPIResult(result))
}

func runToolStream[T dto.TimeoutRequest](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	req, err := parseRequest(c, validate)
	if err != nil {
		return badRequest(c, err.Error())
	}
	args, err := argsFor(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	if len(args) == 0 {
		return internalServerError(c, "internal error: no command generated")
	}
	plan, err := prepareScanExecution(c, req, args)
	if err != nil {
		return scanPreparationError(c, err)
	}
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamExec(execCtx, plan.timeout, plan.args[0], plan.args[1:]...)
	var breakerTripped *atomic.Bool
	if plan.options.Max5xxResponses > 0 {
		lines, breakerTripped = monitorFiveXXResponses(lines, plan.options.Max5xxResponses, cancel)
	}
	done = annotateResult(done, func(result *executor.Result) {
		plan.annotate(result)
		if breakerTripped != nil && breakerTripped.Load() {
			result.Cancelled = true
			result.FailureCode = "target_5xx_threshold"
			result.Warnings = append(result.Warnings, "scan cancelled after target 5xx threshold")
		}
	})
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release, plan.release)
}
