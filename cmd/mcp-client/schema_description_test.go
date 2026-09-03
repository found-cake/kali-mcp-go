package main

import (
	"slices"
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
