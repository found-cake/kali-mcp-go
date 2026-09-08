package results

import (
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func ExecutionMetadataFromResult(result *executor.Result) dto.ExecutionMetadata {
	return dto.ExecutionMetadata{
		Tool:            result.Tool,
		ToolVersion:     result.ToolVersion,
		ArgvRedacted:    result.ArgvRedacted,
		StartedAt:       result.StartedAt,
		EndedAt:         result.StartedAt.Add(result.Duration),
		TimeoutMS:       result.Timeout.Milliseconds(),
		ProcessStarted:  result.ProcessStarted,
		GracefulStopMS:  result.GracefulStop.Milliseconds(),
		DryRun:          result.DryRun,
		Profile:         result.Policy.Profile,
		RateLimit:       result.Policy.RateLimit,
		Concurrency:     result.Policy.Concurrency,
		HealthURL:       result.Policy.HealthURL,
		Max5xxResponses: result.Policy.Max5xxResponses,
		Controls:        result.Controls,
	}
}
