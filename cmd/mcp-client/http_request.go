package main

import (
	"context"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maximumMCPHTTPResponseBytes = 4 * 1024 * 1024

func registerHTTPRequest(server *mcp.Server, kali *kaliclient.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "http_request",
		Description: "Send one bounded HTTP request to an explicitly selected target. Use for manual validation instead of execute_command with curl.",
		InputSchema: httpRequestInputSchema(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.HTTPRequest) (*mcp.CallToolResult, dto.ToolResult, error) {
		result, err := kali.Post(ctx, "/api/tools/http-request", request)
		return textResult("http_request", result, err)
	})
}

func httpRequestInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"url":                map[string]any{"type": "string", "description": "HTTP or HTTPS URL; omit when target_context is supplied"},
			"method":             map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}},
			"headers":            map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"body":               map[string]any{"type": "string", "description": "raw request body; mutually exclusive with json_body"},
			"json_body":          map[string]any{"description": "any JSON value; mutually exclusive with body"},
			"follow_redirects":   map[string]any{"type": "boolean", "description": "follow at most five same-origin redirects"},
			"max_response_bytes": map[string]any{"type": "integer", "minimum": 1, "maximum": maximumMCPHTTPResponseBytes},
			"timeout":            map[string]any{"type": "integer", "minimum": 1, "maximum": 300},
			"target_context":     map[string]any{"type": "string", "description": "signed candidate context returned by resolve_target"},
			"resolution_receipt": map[string]any{"type": "string", "description": "legacy receipt used together with an explicit URL"},
			"profile":            map[string]any{"type": "string", "enum": []string{"safe-recon", "explicit-custom"}},
			"redact_values":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
}
