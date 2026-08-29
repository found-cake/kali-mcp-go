package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerTargetResolver(server *mcp.Server, kali *kaliclient.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "resolve_target",
		Description: "Resolve target candidates from the Kali runtime without rewriting the requested target. Use for loopback addresses or when connectivity must be rechecked.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.ResolveTargetRequest) (*mcp.CallToolResult, dto.TargetResolutionResult, error) {
		result, err := kali.ResolveTarget(ctx, request)
		if err != nil {
			return nil, dto.TargetResolutionResult{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: formatTargetResolution(result)}},
		}, *result, nil
	})
}

func formatTargetResolution(result *dto.TargetResolutionResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "original target: %s\nloopback: %t\n", result.OriginalTarget, result.Loopback)
	for _, candidate := range result.Candidates {
		state := "not probed"
		if candidate.Probed {
			state = "unreachable"
			if candidate.Reachable {
				state = "reachable"
			}
		}
		fmt.Fprintf(&output, "- %s [%s]: %s", candidate.Target, candidate.Scope, state)
		if len(candidate.ResolvedAddresses) > 0 {
			fmt.Fprintf(&output, " (%s)", strings.Join(candidate.ResolvedAddresses, ", "))
		}
		output.WriteByte('\n')
	}
	if result.RecommendedTarget != "" {
		fmt.Fprintf(&output, "recommended target: %s\n", result.RecommendedTarget)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(&output, "warning: %s\n", warning)
	}
	return output.String()
}
