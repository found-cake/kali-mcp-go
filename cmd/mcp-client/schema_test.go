package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolSchemasKeepOptionalFieldsOptional(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	registerTools(server, kaliclient.New("http://unused", time.Second, ""))
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	foundAssessmentStarter := false
	foundResolver := false
	for _, tool := range listed.Tools {
		if tool.Name == "start_blackbox_assessment" {
			foundAssessmentStarter = true
		}
		if tool.Name == "resolve_target" {
			foundResolver = true
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("tool %s has unexpected schema type %T", tool.Name, tool.InputSchema)
		}
		required, _ := schema["required"].([]any)
		for _, field := range required {
			if field == "additional_args" || field == "timeout" {
				t.Fatalf("tool %s incorrectly requires optional field %q", tool.Name, field)
			}
		}
		if tool.Name == "gobuster_scan" {
			properties, _ := schema["properties"].(map[string]any)
			if _, ok := properties["timeout"]; !ok {
				t.Fatal("gobuster schema is missing timeout")
			}
		}
	}
	if !foundResolver {
		t.Fatal("resolve_target tool is missing")
	}
	if foundAssessmentStarter {
		t.Fatal("start_blackbox_assessment duplicates dedicated MCP tools")
	}
}

func TestMCPToolsDoNotExposeServerSideCredentialSessions(t *testing.T) {
	// Given: the complete MCP tool registry.
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	registerTools(server, kaliclient.New("http://unused", time.Second, ""))
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	// When: an orchestrator inspects available tools and scan inputs.
	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	// Then: no server-side credential session operation or handle is exposed.
	for _, tool := range listed.Tools {
		if strings.HasPrefix(tool.Name, "auth_session_") {
			t.Fatalf("server-side credential tool remains exposed: %s", tool.Name)
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("tool %s has unexpected schema type %T", tool.Name, tool.InputSchema)
		}
		properties, _ := schema["properties"].(map[string]any)
		if _, found := properties["session_id"]; found {
			t.Fatalf("tool %s still accepts session_id", tool.Name)
		}
	}
}
