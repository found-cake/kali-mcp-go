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
	sqlmapPlan, err := tools.PrepareSQLMap(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	args := sqlmapPlan.Args()
	scanPlan, err := prepareScanExecution(c, req, args)
	if err != nil {
		sqlmapPlan.Cleanup()
		return scanPreparationError(c, err)
	}
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamExec(execCtx, scanPlan.timeout, scanPlan.args[0], scanPlan.args[1:]...)
	done = annotateResult(done, func(result *executor.Result) {
		count := sqlmapPlan.HTTPRequestCount()
		result.HTTPRequests = &count
		scanPlan.annotate(result)
	})
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release, scanPlan.release, sqlmapPlan.Cleanup)
}
