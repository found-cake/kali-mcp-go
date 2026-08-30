package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	toolmeta "github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func listedTestTools(t *testing.T) []*mcp.Tool {
	t.Helper()
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	if err := registerTools(server, kaliclient.New("http://unused", time.Second, "")); err != nil {
		t.Fatalf("register tools: %v", err)
	}
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
	return listed.Tools
}

func TestCapabilityRegistryMatchesExecutableMCPTools(t *testing.T) {
	t.Parallel()
	metaTools := map[string]bool{
		"get_scan_capabilities": true, "resolve_target": true,
		"result_artifact_read": true, "server_health": true,
	}
	registered := make([]string, 0)
	for _, tool := range listedTestTools(t) {
		if !metaTools[tool.Name] {
			registered = append(registered, tool.Name)
		}
	}
	capabilities := toolmeta.ScanCapabilities()
	declared := make([]string, 0, len(capabilities.Tools))
	for _, capability := range capabilities.Tools {
		declared = append(declared, capability.Tool)
	}
	slices.Sort(registered)
	slices.Sort(declared)
	if !slices.Equal(registered, declared) {
		t.Fatalf("MCP registrations and capability registry differ:\nregistered: %v\n  declared: %v", registered, declared)
	}
}

func TestToolSchemasKeepOptionalFieldsOptional(t *testing.T) {
	t.Parallel()

	tools := listedTestTools(t)
	foundAssessmentStarter := false
	foundResolver := false
	foundCapabilities := false
	foundHTTPRequest := false
	for _, tool := range tools {
		if tool.Name == "start_blackbox_assessment" {
			foundAssessmentStarter = true
		}
		if tool.Name == "resolve_target" {
			foundResolver = true
		}
		if tool.Name == "get_scan_capabilities" {
			foundCapabilities = true
		}
		if tool.Name == "http_request" {
			foundHTTPRequest = true
			properties, _ := schemaProperties(tool.InputSchema)
			jsonBody, _ := properties["json_body"].(map[string]any)
			if jsonBody["type"] == "array" {
				t.Fatal("http_request json_body must accept arbitrary JSON rather than a byte array")
			}
		}
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
	if !foundResolver {
		t.Fatal("resolve_target tool is missing")
	}
	if !foundCapabilities {
		t.Fatal("get_scan_capabilities tool is missing")
	}
	if !foundHTTPRequest {
		t.Fatal("http_request tool is missing")
	}
	if foundAssessmentStarter {
		t.Fatal("start_blackbox_assessment duplicates dedicated MCP tools")
	}
}

func TestRegisteredMCPToolNamesRemainStable(t *testing.T) {
	t.Parallel()

	// Given: the complete MCP registry exposed to an orchestrator.
	tools := listedTestTools(t)
	want := []string{
		"browser_check", "dalfox_scan", "dirb_scan", "enum4linux_scan", "execute_command",
		"feroxbuster_scan", "ffuf_scan", "get_scan_capabilities", "gobuster_scan", "http_request",
		"hydra_attack", "hydra_attack_stream", "john_crack", "jwt_analyze", "metasploit_run",
		"nikto_scan", "nmap_scan", "nuclei_scan", "osv_scan", "resolve_target",
		"result_artifact_read", "retirejs_scan", "server_health", "sqlmap_scan", "tshark_capture",
		"whatweb_scan", "wpscan_analyze",
	}

	// When: the registry is reduced to its machine-routed names.
	got := make([]string, 0, len(tools))
	for _, tool := range tools {
		got = append(got, tool.Name)
	}
	slices.Sort(got)

	// Then: no tool is silently added, removed, or renamed by refactoring.
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected MCP tool names:\n got: %v\nwant: %v", got, want)
	}
}

func TestDependencyToolDescriptionsRouteAvailableEvidence(t *testing.T) {
	t.Parallel()

	descriptions := make(map[string]string)
	for _, tool := range listedTestTools(t) {
		descriptions[tool.Name] = tool.Description
	}
	for _, phrase := range []string{"public JavaScript bundles", "page URL"} {
		if !strings.Contains(descriptions["retirejs_scan"], phrase) {
			t.Fatalf("retirejs_scan description is missing routing phrase %q", phrase)
		}
	}
	for _, phrase := range []string{"manifests", "lockfiles", "inside the Kali runtime", "retirejs_scan"} {
		if !strings.Contains(descriptions["osv_scan"], phrase) {
			t.Fatalf("osv_scan description is missing routing phrase %q", phrase)
		}
	}
}

func schemaProperties(schema any) (map[string]any, bool) {
	object, ok := schema.(map[string]any)
	if !ok {
		return nil, false
	}
	properties, ok := object["properties"].(map[string]any)
	return properties, ok
}

func TestMCPToolsDoNotExposeServerSideCredentialSessions(t *testing.T) {
	// Given: the complete MCP tool registry.
	// When: an orchestrator inspects available tools and scan inputs.
	tools := listedTestTools(t)

	// Then: no server-side credential session operation or handle is exposed.
	for _, tool := range tools {
		if strings.HasPrefix(tool.Name, "auth_session_") {
			t.Fatalf("server-side credential tool remains exposed: %s", tool.Name)
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("tool %s has unexpected schema type %T", tool.Name, tool.InputSchema)
		}
		properties, _ := schema["properties"].(map[string]any)
		if _, found := properties["session_id"]; found {
			t.Fatalf("tool %s still accepts session_id", tool.Name)
		}
	}
}
