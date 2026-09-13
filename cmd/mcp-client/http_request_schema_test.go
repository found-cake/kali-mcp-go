package main

import "testing"

func TestHTTPRequestSchemaExposesTargetBoundVirtualHost(t *testing.T) {
	// Given: the HTTP request tool exposed to an MCP orchestrator.
	tool := listedToolByName(t, "http_request")

	// When: its input contract is inspected.
	properties, ok := schemaProperties(tool.InputSchema)

	// Then: virtual-host testing has a dedicated field instead of a generic Host override.
	if !ok {
		t.Fatal("http_request has an invalid input schema")
	}
	if _, found := properties["virtual_host"]; !found {
		t.Fatal("http_request schema is missing the target-bound virtual_host input")
	}
}
