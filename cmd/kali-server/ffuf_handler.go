package main

import (
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func handleFFUFStream(c fiber.Ctx) error {
	request, err := httpapi.ParseRequest(c, validateFFUFRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	args, err := tools.FFUFArgs(request)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	plan, err := prepareScanExecution(c, request, args)
	if err != nil {
		return scanPreparationError(c, err)
	}
	baseline, err := tools.MeasureSPABaseline(c.Context(), request.URL)
	if err != nil {
		plan.release()
		return httpapi.BadRequest(c, err.Error())
	}
	plan.args, err = tools.ApplyFFUFBaseline(plan.args, baseline)
	if err != nil {
		plan.release()
		return httpapi.BadRequest(c, err.Error())
	}
	plan.spaBaseline = &baseline
	plan.falsePositiveRisk = "high"
	if baseline.Stable {
		plan.falsePositiveRisk = "low"
		plan.extraWarnings = append(plan.extraWarnings, "stable SPA fallback baseline excluded from FFUF results")
	} else {
		plan.extraWarnings = append(plan.extraWarnings, "SPA fallback baseline was unstable; findings may include false positives")
	}
	return executeStreamPlan(c, plan)
}
