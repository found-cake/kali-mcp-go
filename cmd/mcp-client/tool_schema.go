package main

import (
	"fmt"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func executableMCPTool[T any](definition dto.ScanToolCapability) (*mcp.Tool, error) {
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		return nil, fmt.Errorf("infer %s input schema: %w", definition.Tool, err)
	}
	supported := make(map[dto.ScanControl]bool, len(definition.Controls))
	for _, control := range definition.Controls {
		supported[control.Control] = true
	}
	for _, control := range []dto.ScanControl{
		dto.ScanControlTimeout,
		dto.ScanControlRateLimit,
		dto.ScanControlConcurrency,
		dto.ScanControlMaxRequests,
		dto.ScanControlMax5xx,
		dto.ScanControlDryRun,
	} {
		if !supported[control] {
			delete(schema.Properties, string(control))
		}
	}
	if profileSchema, ok := schema.Properties["profile"]; ok {
		profiles := make([]any, 0, len(definition.Profiles)+1)
		for _, profile := range definition.Profiles {
			profiles = append(profiles, string(profile))
		}
		profiles = append(profiles, string(dto.ProfileExplicitCustom))
		profileSchema.Description = "safety profile accepted by this tool"
		profileSchema.Enum = profiles
	}
	return &mcp.Tool{
		Name: definition.Tool, Description: definition.Description,
		InputSchema: schema, OutputSchema: toolResultOutputSchema(),
	}, nil
}
