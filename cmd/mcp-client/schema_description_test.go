package main

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestJWTInputSchemaDistinguishesOfflineParsingFromLiveVerification(t *testing.T) {
	// Given: the JWT tool schema exposed to an MCP orchestrator.
	tool := listedToolByName(t, "jwt_analyze")

	// When: the router inspects each JWT input description.
	properties, ok := schemaProperties(tool.InputSchema)
	if !ok {
		t.Fatal("jwt_analyze has an invalid input schema")
	}

	// Then: offline parsing, live verification, and injection templates are unambiguous.
	assertPropertyDescriptionContains(t, properties, "token", "offline")
	assertPropertyDescriptionContains(t, properties, "target_url", "live")
	assertPropertyDescriptionContains(t, properties, "request_header", "JWT_HERE")
	assertPropertyDescriptionContains(t, properties, "request_cookie", "JWT_HERE")
	for _, phrase := range []string{"offline", "live"} {
		if !strings.Contains(tool.Description, phrase) {
			t.Fatalf("jwt_analyze description is missing routing phrase %q: %q", phrase, tool.Description)
		}
	}
}

func TestToolOutputSchemaSeparatesExecutionFromFindingStatus(t *testing.T) {
	// Given: a representative executable tool's common result schema.
	tool := listedToolByName(t, "nmap_scan")
	properties, ok := schemaProperties(tool.OutputSchema)
	if !ok {
		t.Fatal("nmap_scan has an invalid output schema")
	}

	// When: the orchestrator inspects the common status fields.
	// Then: execution success and security findings describe separate outcomes.
	assertPropertyDescriptionContains(t, properties, "success", "execution")
	assertPropertyDescriptionContains(t, properties, "execution_status", "execution")
	assertPropertyDescriptionContains(t, properties, "finding_status", "finding")
}

func listedToolByName(t *testing.T, name string) *mcp.Tool {
	t.Helper()
	for _, tool := range listedTestTools(t) {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("listed tool not found: %s", name)
	return nil
}

func assertPropertyDescriptionContains(t *testing.T, properties map[string]any, property, phrase string) {
	t.Helper()
	field, ok := properties[property].(map[string]any)
	if !ok {
		t.Fatalf("property %s has an invalid schema", property)
	}
	description, _ := field["description"].(string)
	if !strings.Contains(description, phrase) {
		t.Fatalf("property %s description is missing %q: %q", property, phrase, description)
	}
}
