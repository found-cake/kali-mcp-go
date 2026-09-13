package main

import (
	"encoding/json"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestToolResultOutputSchemaAcceptsClassifiedResult(t *testing.T) {
	result := classifyToolResult("nmap_scan", dto.ToolResult{
		CallID: "call-1", ReturnCode: 0, Stdout: "3000/tcp open http",
	})
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	resolved, err := toolResultOutputSchema().Resolve(nil)
	if err != nil {
		t.Fatalf("resolve output schema: %v", err)
	}
	if err := resolved.Validate(instance); err != nil {
		t.Fatalf("classified result does not match output schema: %v", err)
	}
}

func TestToolResultOutputSchemaSeparatesDiscoveryResponseSize(t *testing.T) {
	// Given: the common executable-tool output schema.
	schema := toolResultOutputSchema()

	// When: an orchestrator inspects structured discovery results.
	discoveries := schema.Properties["discovered_paths"]

	// Then: scanner-reported response bytes are a described field distinct from stdout size.
	if discoveries == nil || discoveries.Items == nil {
		t.Fatalf("discovered_paths item schema is missing: %+v", discoveries)
	}
	responseBytes := discoveries.Items.Properties["response_bytes"]
	if responseBytes == nil || responseBytes.Type != "integer" || responseBytes.Description == "" {
		t.Fatalf("response_bytes schema is ambiguous: %+v", responseBytes)
	}
}
