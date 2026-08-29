package main

import (
	"context"
	"time"

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
	provenance, err := resolveTargetProvenance(req, apiTokenFromContext(c), time.Now().UTC())
	if err != nil {
		return badRequest(c, err.Error())
	}
	if len(args) == 0 {
		return internalServerError(c, "internal error: no command generated")
	}
	timeout := time.Duration(0)
	if timed, ok := any(req).(dto.TimeoutRequest); ok {
		timeout = commandTimeout(timed.GetRequestTimeout())
	}
	result := executor.RunExec(c.Context(), timeout, args[0], args[1:]...)
	result.Target = provenance
	result.Warnings = targetWarnings(req, provenance)
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
	provenance, err := resolveTargetProvenance(req, apiTokenFromContext(c), time.Now().UTC())
	if err != nil {
		return badRequest(c, err.Error())
	}
	if len(args) == 0 {
		return internalServerError(c, "internal error: no command generated")
	}
	execCtx, cancel := context.WithCancel(c.Context())
	timeout := commandTimeout(req.GetRequestTimeout())
	lines, done := executor.StreamExec(execCtx, timeout, args[0], args[1:]...)
	done = annotateResult(done, func(result *executor.Result) {
		result.Target = provenance
		result.Warnings = targetWarnings(req, provenance)
	})
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release)
}
