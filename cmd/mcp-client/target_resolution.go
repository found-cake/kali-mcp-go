package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerTargetResolver(server *mcp.Server, kali *kaliclient.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "resolve_target",
		Description: "Resolve once per target and environment, explicitly select a candidate, then reuse its signed target_context until context_expires_at. Re-resolve only after expiry, connectivity failure, or an environment change.",
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
		if candidate.TargetContext != "" {
			fmt.Fprintf(&output, "  target context valid until: %s\n", candidate.ContextExpiresAt.Format(time.RFC3339))
		}
		if candidate.Probe != nil {
			fmt.Fprintf(&output, "  probe: %s %s:%d in %dms", candidate.Probe.Type, candidate.Probe.Address, candidate.Probe.Port, candidate.Probe.LatencyMS)
			if candidate.Probe.ErrorCode != "" {
				fmt.Fprintf(&output, " (%s)", candidate.Probe.ErrorCode)
			}
			output.WriteByte('\n')
		}
		if candidate.HTTPProbe != nil {
			fmt.Fprintf(&output, "  HTTP probe: status=%d content_type=%s fingerprint=%s\n", candidate.HTTPProbe.StatusCode, candidate.HTTPProbe.ContentType, candidate.HTTPProbe.ServiceFingerprint)
		}
		if candidate.EquivalentServiceGroup != "" {
			fmt.Fprintf(&output, "  equivalent service group: %s\n", candidate.EquivalentServiceGroup)
		}
		if candidate.Recommended {
			fmt.Fprintf(&output, "  recommended option: %s\n", candidate.RecommendationBasis)
		}
		if candidate.BrowserTarget != "" {
			fmt.Fprintf(&output, "  browser target: %s\n", candidate.BrowserTarget)
		}
		fmt.Fprintf(&output, "  network target: %s", candidate.NetworkTarget)
		if candidate.Port > 0 {
			fmt.Fprintf(&output, " (port %d)", candidate.Port)
		}
		output.WriteByte('\n')
	}
	if result.RecommendedTarget != "" {
		fmt.Fprintf(&output, "recommended target: %s\n", result.RecommendedTarget)
	}
	if result.RecommendedBrowserTarget != "" {
		fmt.Fprintf(&output, "recommended browser target: %s\n", result.RecommendedBrowserTarget)
	}
	if result.RecommendedNetworkTarget != "" {
		fmt.Fprintf(&output, "recommended network target: %s", result.RecommendedNetworkTarget)
		if result.RecommendedNetworkPort > 0 {
			fmt.Fprintf(&output, " (port %d)", result.RecommendedNetworkPort)
		}
		output.WriteByte('\n')
	}
	if result.RecommendationBasis != "" {
		fmt.Fprintf(&output, "recommendation basis: %s\n", result.RecommendationBasis)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(&output, "warning: %s\n", warning)
	}
	return output.String()
}
