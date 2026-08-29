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
		Description: "Read a bearer-protected JSON result artifact retained by kali-server for one hour after a scan.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.ArtifactReadRequest) (*mcp.CallToolResult, dto.ArtifactReadResult, error) {
		if strings.TrimSpace(request.ArtifactID) == "" {
			return nil, dto.ArtifactReadResult{}, fmt.Errorf("artifact_id is required")
		}
		result, err := kali.ReadArtifact(ctx, request.ArtifactID)
		if err != nil {
			return nil, dto.ArtifactReadResult{}, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result.Content}}}, *result, nil
	})
}
