package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	toolmeta "github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxCapabilityToolFilters = 16

func registerScanCapabilities(registration toolRegistration) error {
	schema, err := scanCapabilitiesInputSchema()
	if err != nil {
		return err
	}
	description := applyToolInputExample("get_scan_capabilities", "Inspect safety-profile compatibility, bounded coverage, target input formats, supported controls, and effective default wordlists before invoking tools. Set tool_name for one capability or tool_names for a compact batch; omit both for the complete registry. Profile limits are ceilings and apply only when the selected tool lists that control. Safe profiles and a root-only target do not imply exhaustive application coverage.", schema)
	mcp.AddTool(registration.server, &mcp.Tool{
		Name:        "get_scan_capabilities",
		Description: description,
		InputSchema: schema,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.ScanCapabilitiesRequest) (*mcp.CallToolResult, dto.ScanCapabilitiesResult, error) {
		result, err := registration.kali.ScanCapabilities(ctx)
		if err != nil {
			return nil, dto.ScanCapabilitiesResult{}, err
		}
		if err := filterScanCapabilities(result, request); err != nil {
			return nil, dto.ScanCapabilitiesResult{}, err
		}
		if err := attachCapabilityInputSchemas(result, registration.schemas); err != nil {
			return nil, dto.ScanCapabilitiesResult{}, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: formatScanCapabilities(result)}},
		}, *result, nil
	})
	return nil
}

func scanCapabilitiesInputSchema() (*jsonschema.Schema, error) {
	schema, err := jsonschema.For[dto.ScanCapabilitiesRequest](nil)
	if err != nil {
		return nil, fmt.Errorf("infer get_scan_capabilities input schema: %w", err)
	}
	schema.Properties["tool_name"].Enum = stringEnums(toolmeta.ExecutableToolNames())
	minimumItems := 1
	maximumItems := maxCapabilityToolFilters
	schema.Properties["tool_names"].Items = &jsonschema.Schema{Type: "string", Enum: stringEnums(toolmeta.ExecutableToolNames())}
	schema.Properties["tool_names"].MinItems = &minimumItems
	schema.Properties["tool_names"].MaxItems = &maximumItems
	schema.Properties["tool_names"].UniqueItems = true
	schema.AllOf = append(schema.AllOf, &jsonschema.Schema{
		Not: &jsonschema.Schema{Required: []string{"tool_name", "tool_names"}},
	})
	return schema, nil
}

func filterScanCapabilities(result *dto.ScanCapabilitiesResult, request dto.ScanCapabilitiesRequest) error {
	if request.ToolName != "" && len(request.ToolNames) > 0 {
		return fmt.Errorf("tool_name and tool_names are mutually exclusive")
	}
	toolNames := request.ToolNames
	if request.ToolName != "" {
		toolNames = []string{request.ToolName}
	}
	if len(toolNames) == 0 {
		return nil
	}
	if len(toolNames) > maxCapabilityToolFilters {
		return fmt.Errorf("tool_names accepts at most %d entries", maxCapabilityToolFilters)
	}
	capabilities := make(map[string]dto.ScanToolCapability, len(result.Tools))
	for _, tool := range result.Tools {
		capabilities[tool.Tool] = tool
	}
	selected := make(map[string]bool, len(toolNames))
	selectedProfiles := make(map[dto.SafetyProfile]bool)
	filteredTools := make([]dto.ScanToolCapability, 0, len(toolNames))
	for _, toolName := range toolNames {
		if selected[toolName] {
			return fmt.Errorf("duplicate capability tool_name %q", toolName)
		}
		tool, found := capabilities[toolName]
		if !found {
			return fmt.Errorf("unknown capability tool_name %q", toolName)
		}
		selected[toolName] = true
		filteredTools = append(filteredTools, tool)
		for _, profile := range tool.Profiles {
			selectedProfiles[profile] = true
		}
	}
	filteredProfiles := make([]dto.ScanProfileCapability, 0, len(selectedProfiles))
	for _, profile := range result.Profiles {
		if !selectedProfiles[profile.Profile] {
			continue
		}
		profile.Tools = slices.DeleteFunc(slices.Clone(profile.Tools), func(toolName string) bool {
			return !selected[toolName]
		})
		filteredProfiles = append(filteredProfiles, profile)
	}
	filteredWordlists := make([]dto.WordlistCapability, 0, len(result.Wordlists))
	for _, wordlist := range result.Wordlists {
		wordlist.DefaultFor = slices.DeleteFunc(slices.Clone(wordlist.DefaultFor), func(toolName string) bool {
			return !selected[toolName]
		})
		if len(wordlist.DefaultFor) > 0 {
			filteredWordlists = append(filteredWordlists, wordlist)
		}
	}
	result.Tools = filteredTools
	result.Profiles = filteredProfiles
	result.Wordlists = filteredWordlists
	return nil
}

func formatScanCapabilities(result *dto.ScanCapabilitiesResult) string {
	var output strings.Builder
	output.WriteString("profiles:\n")
	for _, profile := range result.Profiles {
		fmt.Fprintf(
			&output,
			"- %s: tools=%s profile_ceilings=rate_limit=%d,concurrency=%d,max_5xx_responses=%d\n",
			profile.Profile, strings.Join(profile.Tools, ","), profile.Limits.RateLimit,
			profile.Limits.Concurrency, profile.Limits.Max5xxResponses,
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
		fmt.Fprintf(&output, "- %s: available=%s target=%s profiles=%s impact=%s mode=%s target_context=%t resume=%t input_schema=embedded", tool.Tool, available, tool.TargetInputFormat, strings.Join(profiles, ","), tool.ImpactLevel, tool.ExecutionMode, tool.RequiresTargetContext, tool.ResumeSupported)
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
