package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	toolmeta "github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAttachCapabilityInputSchemasUsesRegisteredToolSchemas(t *testing.T) {
	t.Parallel()

	// Given: one server capability and the exact schema recorded during MCP registration.
	want := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`)
	result := dto.ScanCapabilitiesResult{Tools: []dto.ScanToolCapability{{Tool: "nmap_scan"}}}
	catalog := toolInputSchemaCatalog{"nmap_scan": want}

	// When: capabilities are prepared for the orchestrator.
	err := attachCapabilityInputSchemas(&result, catalog)
	// Then: the exact registered schema is embedded instead of a hand-maintained duplicate.
	if err != nil {
		t.Fatalf("attach capability schemas: %v", err)
	}
	if result.Tools[0].InputSchemaJSON != string(want) {
		t.Fatalf("input schema differs: got=%s want=%s", result.Tools[0].InputSchemaJSON, want)
	}
}

func TestGetScanCapabilitiesReturnsRegisteredInputSchemas(t *testing.T) {
	// Given: a Kali API returning the canonical capability registry and a connected MCP session.
	kaliAPI := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/tools/capabilities" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(toolmeta.ScanCapabilities()); err != nil {
			t.Errorf("encode capabilities: %v", err)
		}
	}))
	defer kaliAPI.Close()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	if err := registerTools(server, kaliclient.New(kaliAPI.URL, time.Second, "")); err != nil {
		t.Fatalf("register tools: %v", err)
	}
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer clientSession.Close()

	// When: an orchestrator requests the capability surface.
	response, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_scan_capabilities"})
	if err != nil {
		t.Fatalf("call capability tool: %v", err)
	}
	encoded, err := json.Marshal(response.StructuredContent)
	if err != nil {
		t.Fatalf("encode structured capabilities: %v", err)
	}
	var capabilities dto.ScanCapabilitiesResult
	if err := json.Unmarshal(encoded, &capabilities); err != nil {
		t.Fatalf("decode structured capabilities: %v", err)
	}

	// Then: every executable capability includes the exact machine-readable input contract.
	if len(capabilities.Tools) == 0 {
		t.Fatal("capability tool returned no executable tools")
	}
	for _, capability := range capabilities.Tools {
		if capability.InputSchemaJSON == "" || !json.Valid([]byte(capability.InputSchemaJSON)) {
			t.Fatalf("tool %s is missing a valid input schema", capability.Tool)
		}
	}
}
