package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerResultArtifacts(server *mcp.Server, kali *kaliclient.Client) error {
	schema, err := artifactReadInputSchema()
	if err != nil {
		return err
	}
	description := applyToolInputExample("result_artifact_read", "Read any retained artifact completely through bounded pages. The returned call_id identifies this read operation; source_call_id identifies the original tool call that produced the artifact. Use offset and limit for raw byte paging, or start_line and line_count for UTF-8 line paging; the modes are mutually exclusive. Select raw for every artifact or stdout/stderr for tool-result-json. A line over 64 KiB returns line_truncated and continues through next_offset. No cumulative read limit is imposed. Check encoding and redaction_state before handling content.", schema)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "result_artifact_read",
		Description: description,
		InputSchema: schema,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.ArtifactReadRequest) (*mcp.CallToolResult, dto.ArtifactReadResult, error) {
		if strings.TrimSpace(request.ArtifactID) == "" {
			return nil, dto.ArtifactReadResult{}, fmt.Errorf("artifact_id is required")
		}
		result, err := kali.ReadArtifact(ctx, request)
		if err != nil {
			return nil, dto.ArtifactReadResult{}, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result.Content}}}, *result, nil
	})
	return nil
}

func artifactReadInputSchema() (*jsonschema.Schema, error) {
	schema, err := jsonschema.For[dto.ArtifactReadRequest](nil)
	if err != nil {
		return nil, fmt.Errorf("infer result_artifact_read input schema: %w", err)
	}
	section := schema.Properties["section"]
	section.Enum = []any{string(dto.ArtifactSectionRaw), string(dto.ArtifactSectionStdout), string(dto.ArtifactSectionStderr)}
	setSchemaRange(schema.Properties["offset"], 0, 0)
	setSchemaRange(schema.Properties["limit"], 256, 65536)
	setSchemaRange(schema.Properties["start_line"], 1, 0)
	setSchemaRange(schema.Properties["line_count"], 1, 500)
	byteRange := &jsonschema.Schema{AnyOf: []*jsonschema.Schema{{Required: []string{"offset"}}, {Required: []string{"limit"}}}}
	lineRange := &jsonschema.Schema{AnyOf: []*jsonschema.Schema{{Required: []string{"start_line"}}, {Required: []string{"line_count"}}}}
	schema.AllOf = append(schema.AllOf, &jsonschema.Schema{Not: &jsonschema.Schema{AllOf: []*jsonschema.Schema{byteRange, lineRange}}})
	return schema, nil
}

func setSchemaRange(schema *jsonschema.Schema, minimum, maximum float64) {
	schema.Minimum = &minimum
	if maximum != 0 {
		schema.Maximum = &maximum
	}
}
