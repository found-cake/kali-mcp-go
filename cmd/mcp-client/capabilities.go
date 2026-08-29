package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerScanCapabilities(server *mcp.Server, kali *kaliclient.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_scan_capabilities",
		Description: "Inspect safety-profile compatibility, target input formats, supported controls, and effective default wordlists before invoking tools.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, dto.ScanCapabilitiesResult, error) {
		result, err := kali.ScanCapabilities(ctx)
		if err != nil {
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
		fmt.Fprintf(&output, "- %s: %s\n", profile.Profile, strings.Join(profile.Tools, ", "))
	}
	output.WriteString("tools:\n")
	for _, tool := range result.Tools {
		profiles := make([]string, 0, len(tool.Profiles))
		for _, profile := range tool.Profiles {
			profiles = append(profiles, string(profile))
		}
		controls := make([]string, 0, len(tool.SupportedControls))
		for _, control := range tool.SupportedControls {
			controls = append(controls, string(control))
		}
		fmt.Fprintf(&output, "- %s: target=%s profiles=%s", tool.Tool, tool.TargetInputFormat, strings.Join(profiles, ","))
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
