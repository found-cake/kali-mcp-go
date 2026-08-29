package main

import (
	"context"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func handleSQLMapStream(c fiber.Ctx) error {
	req, err := parseRequest(c, validateSQLMapRequest)
	if err != nil {
		return badRequest(c, err.Error())
	}
	plan, err := tools.PrepareSQLMap(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	args := plan.Args()
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamExec(execCtx, commandTimeout(req.Timeout), args[0], args[1:]...)
	done = annotateResult(done, func(result *executor.Result) {
		count := plan.HTTPRequestCount()
		result.HTTPRequests = &count
		result.Warnings = tools.TargetWarnings(req)
	})
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release, plan.Cleanup)
}
