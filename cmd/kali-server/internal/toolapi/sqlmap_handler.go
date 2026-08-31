package toolapi

import (
	"context"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleSQLMapStream(c fiber.Ctx) error {
	req, err := httpapi.ParseRequest(c, validateSQLMapRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	sqlmapPlan, err := tools.PrepareSQLMap(req)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	args := sqlmapPlan.Args()
	scanPlan, err := prepareScanExecution(c, req, args)
	if err != nil {
		sqlmapPlan.Cleanup()
		return scanPreparationError(c, err)
	}
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamExec(execCtx, scanPlan.timeout, scanPlan.args[0], scanPlan.args[1:]...)
	lines = results.ProtectStream(execCtx, lines, req)
	done = annotateResult(done, func(result *executor.Result) {
		analysis := sqlmapPlan.Analysis(result.Stdout, req.TestParameters)
		count := analysis.HTTPRequests
		result.HTTPRequests = &count
		result.RequestCountSource = dto.RequestCountParsed
		result.SQLMapAnalysis = &analysis
		scanPlan.annotate(result)
	})
	release := httpapi.RetainExecutionLease(c)
	return httpapi.SendToolStream(c, lines, done, cancel, release, scanPlan.release, sqlmapPlan.Cleanup)
}
