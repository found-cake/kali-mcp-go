package main

import (
	"encoding/json"
	"testing"
)

func TestExecutableToolOutputSchemasStayCompactAndUniform(t *testing.T) {
	metaTools := map[string]bool{
		"get_scan_capabilities": true, "resolve_target": true,
		"result_artifact_read": true, "server_health": true,
		"scan_job_status": true, "scan_job_result": true, "scan_job_cancel": true,
		"run_tool_async": true,
	}
	var canonical []byte
	for _, tool := range listedTestTools(t) {
		if metaTools[tool.Name] {
			continue
		}
		resultSchema, properties, ok := toolResultSchema(tool.OutputSchema)
		if !ok {
			t.Fatalf("tool %s has an invalid output schema", tool.Name)
		}
		encoded, err := json.Marshal(resultSchema)
		if err != nil {
			t.Fatalf("marshal %s output schema: %v", tool.Name, err)
		}
		if len(encoded) > 5000 {
			t.Fatalf("tool %s output schema is too large: %d bytes", tool.Name, len(encoded))
		}
		if canonical == nil {
			canonical = encoded
		} else if string(encoded) != string(canonical) {
			t.Fatalf("tool %s output schema differs from the common envelope", tool.Name)
		}
		for _, field := range []string{"call_id", "execution_status", "finding_status", "finding_types", "partial_results", "artifacts"} {
			if _, found := properties[field]; !found {
				t.Fatalf("tool %s output schema is missing %s", tool.Name, field)
			}
		}
	}
}

func toolResultSchema(schema any) (any, map[string]any, bool) {
	if properties, ok := schemaProperties(schema); ok {
		return schema, properties, true
	}
	object, ok := schema.(map[string]any)
	if !ok {
		return nil, nil, false
	}
	alternatives, ok := object["oneOf"].([]any)
	if !ok {
		return nil, nil, false
	}
	for _, alternative := range alternatives {
		properties, valid := schemaProperties(alternative)
		if valid {
			if _, found := properties["call_id"]; found {
				return alternative, properties, true
			}
		}
	}
	return nil, nil, false
}

func TestDependencyToolsExposeRoutableInputs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		tool   string
		fields []string
	}{
		{tool: "browser_check", fields: []string{"url", "capture_network"}},
		{tool: "retirejs_scan", fields: []string{"path", "url", "script_urls", "target_context"}},
		{tool: "osv_scan", fields: []string{"path"}},
	} {
		properties, ok := schemaProperties(listedToolByName(t, test.tool).InputSchema)
		if !ok {
			t.Fatalf("tool %s has an invalid input schema", test.tool)
		}
		for _, field := range test.fields {
			if _, found := properties[field]; !found {
				t.Fatalf("tool %s is missing routable input %s", test.tool, field)
			}
		}
	}
}
