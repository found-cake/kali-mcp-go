package main

import (
	"context"
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
	for _, tool := range listed.Tools {
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
}
