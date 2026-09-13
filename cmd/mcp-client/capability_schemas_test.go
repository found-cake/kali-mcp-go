package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	toolmeta "github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestScanCapabilitiesInputSchemaExposesSingleAndBatchToolFilters(t *testing.T) {
	t.Parallel()

	// Given: the executable tool registry.
	toolNames := toolmeta.ExecutableToolNames()

	// When: the capability tool input schema is generated.
	schema, err := scanCapabilitiesInputSchema()

	// Then: callers can select one tool or a bounded set from the same registry.
	if err != nil {
		t.Fatalf("build capability input schema: %v", err)
	}
	single, found := schema.Properties["tool_name"]
	if !found {
		t.Fatal("get_scan_capabilities schema is missing tool_name")
	}
	batch, found := schema.Properties["tool_names"]
	if !found || batch.Items == nil || batch.MaxItems == nil || *batch.MaxItems != maxCapabilityToolFilters || !batch.UniqueItems {
		t.Fatalf("get_scan_capabilities batch schema is incomplete: %+v", batch)
	}
	for _, toolName := range toolNames {
		if !slices.Contains(single.Enum, any(toolName)) || !slices.Contains(batch.Items.Enum, any(toolName)) {
			t.Fatalf("tool_name enum is missing %s", toolName)
		}
	}
}

func TestScanCapabilitiesInputSchemaRejectsAmbiguousBatchFilters(t *testing.T) {
	// Given: the resolved capability input schema.
	schema, err := scanCapabilitiesInputSchema()
	if err != nil {
		t.Fatalf("build capability input schema: %v", err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("resolve capability input schema: %v", err)
	}

	// When: a caller combines the single and batch selectors.
	err = resolved.Validate(map[string]any{
		"tool_name": "nmap_scan", "tool_names": []any{"whatweb_scan"},
	})

	// Then: the ambiguous selection is rejected before execution.
	if err == nil {
		t.Fatal("schema accepted both tool_name and tool_names")
	}
}

func TestFilterScanCapabilitiesReturnsCompactRequestedTools(t *testing.T) {
	t.Parallel()

	// Given: the complete capability registry.
	result := toolmeta.ScanCapabilities()
	request := dto.ScanCapabilitiesRequest{ToolNames: []string{"john_crack", "feroxbuster_scan"}}

	// When: two tools are selected for one compact response.
	err := filterScanCapabilities(&result, request)

	// Then: tools retain request order and unrelated profile and wordlist entries are removed.
	if err != nil {
		t.Fatalf("filter capabilities: %v", err)
	}
	if len(result.Tools) != 2 || result.Tools[0].Tool != "john_crack" || result.Tools[1].Tool != "feroxbuster_scan" {
		t.Fatalf("unexpected filtered tools: %+v", result.Tools)
	}
	selected := map[string]bool{"john_crack": true, "feroxbuster_scan": true}
	for _, profile := range result.Profiles {
		if len(profile.Tools) == 0 {
			t.Fatalf("empty profile retained: %+v", profile)
		}
		for _, toolName := range profile.Tools {
			if !selected[toolName] {
				t.Fatalf("unrelated profile tool retained: %+v", profile)
			}
		}
	}
	for _, wordlist := range result.Wordlists {
		if len(wordlist.DefaultFor) == 0 {
			t.Fatalf("unrelated wordlist retained: %+v", wordlist)
		}
		for _, toolName := range wordlist.DefaultFor {
			if !selected[toolName] {
				t.Fatalf("unrelated wordlist tool retained: %+v", wordlist)
			}
		}
	}
}

func TestFilterScanCapabilitiesPreservesSingleToolSelection(t *testing.T) {
	t.Parallel()

	// Given: the complete capability registry and the legacy single selector.
	result := toolmeta.ScanCapabilities()
	request := dto.ScanCapabilitiesRequest{ToolName: "feroxbuster_scan"}

	// When: one tool is selected for a compact response.
	err := filterScanCapabilities(&result, request)

	// Then: the existing selector still returns only the requested tool.
	if err != nil {
		t.Fatalf("filter capabilities: %v", err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Tool != "feroxbuster_scan" {
		t.Fatalf("unexpected filtered tools: %+v", result.Tools)
	}
}

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
