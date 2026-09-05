package main

import (
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestJWTInputSchemaExposesOfflineAndLiveVerificationInputs(t *testing.T) {
	// Given: the JWT tool schema exposed to an MCP orchestrator.
	tool := listedToolByName(t, "jwt_analyze")

	// When: the router inspects each JWT input description.
	properties, ok := schemaProperties(tool.InputSchema)
	if !ok {
		t.Fatal("jwt_analyze has an invalid input schema")
	}

	// Then: offline parsing and optional live request templates are separate fields.
	for _, field := range []string{"token", "target_url", "request_header", "request_cookie"} {
		fieldSchema, found := properties[field]
		if !found {
			t.Fatalf("jwt_analyze is missing %s", field)
		}
		object, ok := fieldSchema.(map[string]any)
		if !ok || object["type"] != "string" {
			t.Fatalf("jwt_analyze field %s is not a string schema: %+v", field, fieldSchema)
		}
	}
	root, ok := tool.InputSchema.(map[string]any)
	if !ok || !schemaRequiredField(root, "token") {
		t.Fatal("jwt_analyze must require the offline token input")
	}
	unsafeSchema, found := properties["allow_unsafe"].(map[string]any)
	if !found || unsafeSchema["type"] != "boolean" {
		t.Fatalf("jwt_analyze allow_unsafe schema is missing or invalid: %+v", properties["allow_unsafe"])
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
	// Then: execution and finding outcomes expose independent value sets.
	if got := schemaEnumValues(properties["execution_status"]); !slices.Equal(got, []string{"succeeded", "failed", "timed_out", "cancelled"}) {
		t.Fatalf("unexpected execution status values: %v", got)
	}
	if got := schemaEnumValues(properties["finding_status"]); !slices.Equal(got, []string{"detected", "not_detected", "inconclusive", "unknown"}) {
		t.Fatalf("unexpected finding status values: %v", got)
	}
}

func TestToolInputSchemasExposeOnlyCompatibleProfiles(t *testing.T) {
	// Given: tools with different safety-profile compatibility.
	tests := []struct {
		tool     string
		profiles []string
	}{
		{tool: "nmap_scan", profiles: []string{"safe-recon", "explicit-custom"}},
		{tool: "browser_check", profiles: []string{"browser-xss-confirm", "explicit-custom"}},
	}

	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			// When: an orchestrator inspects the tool's profile schema.
			properties, ok := schemaProperties(listedToolByName(t, test.tool).InputSchema)
			if !ok {
				t.Fatalf("%s has an invalid input schema", test.tool)
			}

			// Then: only profiles accepted by that tool are selectable.
			profileSchema, ok := properties["profile"].(map[string]any)
			if !ok {
				t.Fatalf("%s has an invalid profile schema", test.tool)
			}
			values, ok := profileSchema["enum"].([]any)
			if !ok {
				t.Fatalf("%s profile schema has no enum: %+v", test.tool, profileSchema)
			}
			profiles := make([]string, 0, len(values))
			for _, value := range values {
				profile, ok := value.(string)
				if !ok {
					t.Fatalf("%s profile enum contains %T", test.tool, value)
				}
				profiles = append(profiles, profile)
			}
			if !slices.Equal(profiles, test.profiles) {
				t.Fatalf("%s profiles=%v want=%v", test.tool, profiles, test.profiles)
			}
		})
	}
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

func schemaRequiredField(schema map[string]any, field string) bool {
	required, _ := schema["required"].([]any)
	return slices.Contains(required, any(field))
}

func schemaEnumValues(schema any) []string {
	object, ok := schema.(map[string]any)
	if !ok {
		return nil
	}
	values, _ := object["enum"].([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil
		}
		result = append(result, text)
	}
	return result
}
