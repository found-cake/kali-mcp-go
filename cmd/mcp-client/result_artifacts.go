package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerResultArtifacts(server *mcp.Server, kali *kaliclient.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "result_artifact_read",
		Description: "Read one bounded page from a retained artifact. Check encoding and redaction_state: text is UTF-8, binary evidence is base64, and sensitive_unredacted content requires caller-side protection. Continue with next_offset while has_more is true.",
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
}
