package toolapi

import (
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func gobusterExecutionSpec() toolExecutionSpec[dto.GobusterRequest] {
	return toolExecutionSpec[dto.GobusterRequest]{
		validate: validateGobusterRequest,
		argsFor:  tools.GobusterArgs,
		decorate: func(request dto.GobusterRequest, plan *scanExecutionPlan) error {
			if request.Mode != "" && request.Mode != "dir" {
				return nil
			}
			baseline, err := tools.MeasureSPABaseline(plan.context, request.URL)
			if err != nil {
				return err
			}
			plan.args, err = tools.ApplyGobusterBaseline(plan.args, baseline)
			if err != nil {
				return err
			}
			plan.spaBaseline = &baseline
			plan.falsePositiveRisk = "high"
			if baseline.Stable {
				plan.falsePositiveRisk = "low"
				plan.extraWarnings = append(plan.extraWarnings, "stable SPA fallback baseline excluded from Gobuster results")
				return nil
			}
			plan.extraWarnings = append(plan.extraWarnings, "SPA fallback baseline was unstable; Gobuster findings may include false positives")
			return nil
		},
	}
}
