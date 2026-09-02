package toolapi

import (
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleFeroxbusterStream(c fiber.Ctx) error {
	return withPreparedTool(c, feroxbusterExecutionSpec(), func(plan *scanExecutionPlan) error {
		return executeStreamPlan(c, plan)
	})
}

func feroxbusterExecutionSpec() toolExecutionSpec[dto.FeroxbusterRequest] {
	return toolExecutionSpec[dto.FeroxbusterRequest]{
		validate: validateFeroxbusterRequest,
		argsFor:  tools.FeroxbusterArgs,
		decorate: func(request dto.FeroxbusterRequest, plan *scanExecutionPlan) error {
			baseline, err := tools.MeasureSPABaseline(plan.context, request.URL)
			if err != nil {
				return err
			}
			plan.args, err = tools.ApplyFeroxbusterBaseline(plan.args, baseline)
			if err != nil {
				return err
			}
			plan.spaBaseline = &baseline
			plan.falsePositiveRisk = "high"
			if baseline.Stable {
				plan.falsePositiveRisk = "low"
				plan.extraWarnings = append(plan.extraWarnings, "stable SPA fallback baseline excluded from Feroxbuster results")
				return nil
			}
			plan.extraWarnings = append(plan.extraWarnings, "SPA fallback baseline was unstable; Feroxbuster findings may include false positives")
			return nil
		},
	}
}
