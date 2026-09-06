package toolapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const nucleiPreviewTimeout = 30 * time.Second

func decorateNucleiExecution(request dto.NucleiRequest, plan *scanExecutionPlan) error {
	preview, err := previewNucleiTemplates(plan.context, request)
	if err != nil {
		if request.DryRun {
			return err
		}
		plan.extraWarnings = append(plan.extraWarnings, "Nuclei execution preflight unavailable: "+err.Error())
		return nil
	}
	if preview.TemplatesMatched > 0 {
		preview.RequestEstimateAvailable = true
		preview.MinimumRequestEstimate = preview.TemplatesMatched
		preview.RequestEstimateReason = "lower bound assumes one request per selected template; workflows and multi-request templates can require more"
	}
	if preview.TemplatesMatched > 0 && plan.options.RateLimit > 0 {
		requestSeconds := (preview.TemplatesMatched + plan.options.RateLimit - 1) / plan.options.RateLimit
		minimumDuration := time.Duration(requestSeconds)*time.Second + scanStartupGrace("nuclei")
		preview.EstimatedMinimumDurationMS = minimumDuration.Milliseconds()
		preview.TimeoutLikelyInsufficient = plan.timeout < minimumDuration
		if preview.TimeoutLikelyInsufficient {
			plan.extraWarnings = append(plan.extraWarnings, fmt.Sprintf(
				"Nuclei selected %d templates; the %s timeout is below the %s lower-bound estimate",
				preview.TemplatesMatched, plan.timeout, minimumDuration,
			))
		}
	}
	plan.nucleiPreview = preview
	return nil
}

func previewNucleiTemplates(ctx context.Context, request dto.NucleiRequest) (*dto.NucleiPreviewMetadata, error) {
	args, err := tools.NucleiTemplateListArgs(request)
	if err != nil {
		return nil, err
	}
	result := executor.RunExec(ctx, nucleiPreviewTimeout, args[0], args[1:]...)
	if result.ReturnCode != 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("list Nuclei templates: %w", err)
		}
		message := strings.TrimSpace(result.Stderr)
		if message == "" {
			message = strings.TrimSpace(result.Stdout)
		}
		return nil, fmt.Errorf("list Nuclei templates: %s", message)
	}
	preview := tools.SummarizeNucleiTemplateList(request, result.Stdout)
	return &preview, nil
}
