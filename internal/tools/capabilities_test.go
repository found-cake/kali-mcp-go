package tools

import (
	"os"
	"slices"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestScanCapabilitiesCoverEveryExecutableToolWithRoutingMetadata(t *testing.T) {
	want := []string{
		"browser_check", "dalfox_scan", "dirb_scan", "enum4linux_scan", "execute_command",
		"feroxbuster_scan", "ffuf_scan", "gobuster_scan", "http_request", "hydra_attack",
		"hydra_attack_stream", "john_crack", "jwt_analyze", "metasploit_run", "nikto_scan",
		"nmap_scan", "nuclei_scan", "osv_scan", "retirejs_scan", "sqlmap_scan",
		"tshark_capture", "whatweb_scan", "wpscan_analyze",
	}
	capabilities := ScanCapabilities()
	got := make([]string, 0, len(capabilities.Tools))
	for _, capability := range capabilities.Tools {
		got = append(got, capability.Tool)
		if capability.RuntimeTool == "" || capability.Description == "" || capability.Endpoint == "" {
			t.Fatalf("tool is missing runtime routing metadata: %+v", capability)
		}
		if capability.InputSchemaSource != "mcp_tools_list" || capability.ExecutionMode == "" || capability.ImpactLevel == "" {
			t.Fatalf("tool is missing orchestration metadata: %+v", capability)
		}
		for _, control := range capability.Controls {
			if control.Control == "" || control.Enforcement == "" || !slices.Contains(capability.SupportedControls, control.Control) {
				t.Fatalf("tool control metadata is inconsistent: %+v", capability)
			}
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("capability tools differ from executable MCP tools:\n got: %v\nwant: %v", got, want)
	}

	explicit := findToolCapability(t, capabilities.Tools, "execute_command")
	if explicit.ImpactLevel != dto.ImpactArbitraryExecution {
		t.Fatalf("execute_command impact is not explicit: %+v", explicit)
	}
}

func TestScanCapabilitiesReportConfiguredDefaultWordlists(t *testing.T) {
	// Given: an available directory wordlist selected through configuration.
	wordlist, err := os.CreateTemp(t.TempDir(), "paths-*.txt")
	if err != nil {
		t.Fatalf("create wordlist: %v", err)
	}
	if _, err := wordlist.WriteString("admin\nlogin\n"); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	if err := wordlist.Close(); err != nil {
		t.Fatalf("close wordlist: %v", err)
	}
	t.Setenv(defaultDirWordlistEnv, wordlist.Name())

	// When: an orchestrator requests scan capabilities.
	capabilities := ScanCapabilities()

	// Then: the effective default is discoverable before a Feroxbuster call.
	if len(capabilities.Wordlists) == 0 {
		t.Fatal("directory wordlist capability is missing")
	}
	directory := capabilities.Wordlists[0]
	if directory.Name != "directory-discovery" {
		t.Fatalf("unexpected first wordlist: %+v", directory)
	}
	if directory.Path != wordlist.Name() || !directory.Available || directory.SizeBytes == 0 {
		t.Fatalf("unexpected directory wordlist: %+v", directory)
	}
	if !slices.Contains(directory.DefaultFor, "feroxbuster_scan") {
		t.Fatalf("feroxbuster default missing: %+v", directory.DefaultFor)
	}
}
