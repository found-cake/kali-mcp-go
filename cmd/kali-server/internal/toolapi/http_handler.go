package toolapi

import (
	"context"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/httpexec"
	"github.com/found-cake/kali-mcp-go/internal/jobs"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleHTTPRequest(c fiber.Ctx) error {
	request, err := httpapi.ParseRequest(c, httpexec.Validate)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	if err := tools.ValidateScanProfile("http-request", request.ScanOptions); err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	provenance, err := targeting.ResolveProvenance(request, httpapi.APIToken(c), time.Now().UTC())
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	release := func() {}
	if scheduler := httpapi.Scheduler(c); scheduler != nil {
		release, err = scheduler.Acquire(targeting.SchedulerKey(request.URL, provenance), 1)
		if err != nil {
			return scanPreparationError(c, err)
		}
	}
	if httpapi.AsyncRequested(c) {
		callID := httpapi.CallID(c)
		artifacts := httpapi.ArtifactStore(c)
		return executeAsyncTask(c, asyncTaskSpec{
			callID: callID, tool: "http-request", timeout: httpexec.RequestTimeout(request.Timeout),
			cleanup: []func(){release},
			run: func(ctx context.Context, _ jobs.ProgressReporter) dto.ToolResult {
				result := httpexec.Execute(ctx, httpexec.Input{CallID: callID, Request: request, Target: provenance})
				results.Protect(artifacts, result, request)
				return results.ToToolResult(result)
			},
		})
	}
	defer release()
	result := httpexec.Execute(c.Context(), httpexec.Input{
		CallID: httpapi.CallID(c), Request: request, Target: provenance,
	})
	return httpapi.WriteToolResult(c, result, request)
}
