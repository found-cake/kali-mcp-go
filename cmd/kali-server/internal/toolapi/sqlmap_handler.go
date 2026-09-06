package toolapi

import (
	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
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
	if req.RequestFile != "" {
		req.RequestFile = sqlmapPlan.RequestFile()
	}
	args := sqlmapPlan.Args()
	scanPlan, err := prepareScanExecution(c, req, args)
	if err != nil {
		sqlmapPlan.Cleanup()
		return scanPreparationError(c, err)
	}
	scanPlan.ephemeralPaths = []string{sqlmapPlan.EphemeralPath()}
	return executeToolStream(c, streamExecution{
		plan: scanPlan,
		beforeAnnotate: func(result *executor.Result) {
			analysis := sqlmapPlan.Analysis(result.Stdout+"\n"+result.Stderr, req.TestParameters)
			count := analysis.HTTPRequests
			result.HTTPRequests = &count
			result.RequestCountSource = dto.RequestCountParsed
			result.SQLMapAnalysis = &analysis
			if analysis.AbortedOnHTTPCode != 0 {
				result.FailureCode = "sqlmap_abort_code"
			}
		},
		cleanups: []func(){sqlmapPlan.Cleanup},
	})
}
