package main

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAsyncExecutionUsesOneGenericToolInsteadOfPerToolFlags(t *testing.T) {
	// Given: the complete MCP registry with synchronous executable tools.
	tools := map[string]*mcp.Tool{}
	for _, tool := range listedTestTools(t) {
		tools[tool.Name] = tool
	}

	// When: the generic and dedicated input schemas are inspected.
	asyncTool, present := tools["run_tool_async"]
	if !present {
		t.Fatal("run_tool_async is not registered")
	}
	asyncProperties, asyncSchema := schemaProperties(asyncTool.InputSchema)
	_, toolName := asyncProperties["tool_name"]
	arguments, argumentsPresent := asyncProperties["arguments"].(map[string]any)

	// Then: only the generic dispatcher exposes asynchronous execution and accepts an argument object.
	if !asyncSchema || !toolName || !argumentsPresent || arguments["type"] != "object" {
		t.Fatalf("run_tool_async schema is incomplete: %+v", asyncProperties)
	}
	for name, tool := range tools {
		if name == "run_tool_async" {
			continue
		}
		properties, _ := schemaProperties(tool.InputSchema)
		if _, found := properties["async"]; found {
			t.Fatalf("tool %s still exposes an async flag", name)
		}
	}
}
