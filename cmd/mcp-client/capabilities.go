package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerScanCapabilities(registration toolRegistration) {
	mcp.AddTool(registration.server, &mcp.Tool{
		Name:        "get_scan_capabilities",
		Description: "Inspect safety-profile compatibility, bounded coverage, target input formats, supported controls, and effective default wordlists before invoking tools. Safe profiles and a root-only target do not imply exhaustive application coverage.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, dto.ScanCapabilitiesResult, error) {
		result, err := registration.kali.ScanCapabilities(ctx)
		if err != nil {
			return nil, dto.ScanCapabilitiesResult{}, err
		}
		if err := attachCapabilityInputSchemas(result, registration.schemas); err != nil {
			return nil, dto.ScanCapabilitiesResult{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: formatScanCapabilities(result)}},
		}, *result, nil
	})
}

func formatScanCapabilities(result *dto.ScanCapabilitiesResult) string {
	var output strings.Builder
	output.WriteString("profiles:\n")
	for _, profile := range result.Profiles {
		fmt.Fprintf(
			&output,
			"- %s: tools=%s limits=rate_limit=%d,concurrency=%d,timeout_request_budget=%d,max_5xx_responses=%d\n",
			profile.Profile, strings.Join(profile.Tools, ","), profile.Limits.RateLimit,
			profile.Limits.Concurrency, profile.Limits.TimeoutRequestBudget, profile.Limits.Max5xxResponses,
		)
	}
	output.WriteString("tools:\n")
	for _, tool := range result.Tools {
		profiles := make([]string, 0, len(tool.Profiles))
		for _, profile := range tool.Profiles {
			profiles = append(profiles, string(profile))
		}
		controls := make([]string, 0, len(tool.Controls))
		for _, control := range tool.Controls {
			controls = append(controls, string(control.Control)+":"+string(control.Enforcement))
		}
		available := "unknown"
		if tool.AvailabilityChecked {
			available = fmt.Sprintf("%t", tool.Available)
		}
		fmt.Fprintf(&output, "- %s: available=%s target=%s profiles=%s impact=%s mode=%s target_context=%t async=%t resume=%t input_schema=embedded", tool.Tool, available, tool.TargetInputFormat, strings.Join(profiles, ","), tool.ImpactLevel, tool.ExecutionMode, tool.RequiresTargetContext, tool.AsyncSupported, tool.ResumeSupported)
		if len(controls) > 0 {
			fmt.Fprintf(&output, " controls=%s", strings.Join(controls, ","))
		}
		output.WriteByte('\n')
	}
	output.WriteString("wordlists:\n")
	for _, wordlist := range result.Wordlists {
		fmt.Fprintf(&output, "- %s: path=%s available=%t size_bytes=%d default_for=%s\n", wordlist.Name, wordlist.Path, wordlist.Available, wordlist.SizeBytes, strings.Join(wordlist.DefaultFor, ","))
	}
	return output.String()
}
