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

func registerAuthSessions(server *mcp.Server, kali *kaliclient.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "auth_session_create",
		Description: "Store target-bound HTTP credentials inside Kali and return an opaque session handle. Raw secrets are never returned.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.AuthSessionCreateRequest) (*mcp.CallToolResult, dto.AuthSessionMetadata, error) {
		result, err := kali.CreateAuthSession(ctx, request)
		if err != nil {
			return nil, dto.AuthSessionMetadata{}, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: formatAuthSession(*result)}}}, *result, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "auth_session_list",
		Description: "List active target authentication session metadata without exposing credentials.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, dto.AuthSessionListResult, error) {
		result, err := kali.ListAuthSessions(ctx)
		if err != nil {
			return nil, dto.AuthSessionListResult{}, err
		}
		lines := make([]string, 0, len(result.Sessions))
		for _, session := range result.Sessions {
			lines = append(lines, formatAuthSession(session))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(lines, "\n")}}}, *result, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "auth_session_delete",
		Description: "Immediately discard a target authentication session and its retained credentials.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.AuthSessionDeleteRequest) (*mcp.CallToolResult, struct{}, error) {
		if err := kali.DeleteAuthSession(ctx, request.SessionID); err != nil {
			return nil, struct{}{}, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "authentication session deleted"}}}, struct{}{}, nil
	})
}

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

func formatAuthSession(session dto.AuthSessionMetadata) string {
	return fmt.Sprintf("session: %s (%s)\norigin: %s\nexpires: %s\nheaders: %s\ncookie: %t",
		session.Label, session.SessionID, session.Origin, session.ExpiresAt.Format(time.RFC3339), strings.Join(session.HeaderNames, ", "), session.HasCookie)
}
