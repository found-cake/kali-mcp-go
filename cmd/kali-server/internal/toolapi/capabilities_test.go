package toolapi

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestHandleScanCapabilitiesReturnsProfileToolCompatibility(t *testing.T) {
	// Given: the stateless capabilities endpoint.
	app := fiber.New()
	app.Get("/capabilities", handleScanCapabilities)

	// When: an orchestrator inspects compatibility before scanning.
	request, err := http.NewRequest(http.MethodGet, "/capabilities", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	var result dto.ScanCapabilitiesResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Then: the endpoint returns the same non-empty policy contract used at execution.
	if response.StatusCode != fiber.StatusOK || len(result.Profiles) == 0 || len(result.Tools) == 0 {
		t.Fatalf("unexpected capabilities response: status=%d result=%+v", response.StatusCode, result)
	}
	foundNiktoInventory := false
	for _, tool := range result.Tools {
		if tool.Tool == "nikto_scan" && tool.PluginInventory != nil && tool.PluginInventory.Source == "nikto -list-plugins" {
			foundNiktoInventory = true
		}
	}
	if !foundNiktoInventory {
		t.Fatalf("Nikto plugin inventory is missing: %+v", result.Tools)
	}
}

func TestToolStatusTracksWordlistReadinessSeparatelyFromEssentialFlagSemantics(t *testing.T) {
	// Given: available binaries, one usable directory wordlist, and one missing John wordlist.
	directoryWordlist, err := os.CreateTemp(t.TempDir(), "dir-wordlist-*.txt")
	if err != nil {
		t.Fatalf("create dir wordlist: %v", err)
	}
	defer directoryWordlist.Close()
	t.Setenv("KALI_MCP_DIR_WORDLIST", directoryWordlist.Name())
	t.Setenv("KALI_MCP_JOHN_WORDLIST", "/missing/john-wordlist.txt")

	// When: readiness is calculated with a missing non-essential scanner.
	status := toolStatus(func(name string) bool {
		return name != "sqlmap"
	})

	// Then: wordlist readiness is tool-specific and the aggregate uses only essentials.
	if !status["gobuster"] || !status["dirb"] {
		t.Fatalf("expected directory tools to be ready: %v", status)
	}
	if status["john"] {
		t.Fatalf("expected john to be unavailable: %v", status)
	}
	if !allEssentialToolsAvailable(status) {
		t.Fatalf("expected the essential aggregate to ignore sqlmap: %v", status)
	}
}

func TestHandleHealthUsesEssentialSubsetForAggregateFlag(t *testing.T) {
	// Given: missing default wordlists for directory tools and John.
	t.Setenv("KALI_MCP_DIR_WORDLIST", "/missing/dir-wordlist.txt")
	t.Setenv("KALI_MCP_JOHN_WORDLIST", "/missing/john-wordlist.txt")
	app := fiber.New()
	app.Get("/health", handleHealth)

	// When: the health endpoint evaluates tool readiness.
	request, err := http.NewRequest(http.MethodGet, "/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	var result dto.HealthResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Then: missing essential tools degrade health and John remains independently unavailable.
	if result.AllEssentialToolsAvailable && (!result.ToolsStatus["gobuster"] || !result.ToolsStatus["dirb"]) {
		t.Fatalf("essential aggregate reported ready: %+v", result)
	}
	if result.Status != "degraded" || result.ToolsStatus["john"] {
		t.Fatalf("unexpected degraded health: %+v", result)
	}
}

func TestToolStatusTracksNucleiTemplateReadiness(t *testing.T) {
	tests := []struct {
		name          string
		prepare       func(*testing.T) string
		expectedReady bool
	}{
		{name: "missing", prepare: func(t *testing.T) string { return t.TempDir() }, expectedReady: false},
		{name: "installed", prepare: func(t *testing.T) string {
			directory := t.TempDir()
			if err := os.WriteFile(directory+"/.checksum", []byte("ready"), 0o600); err != nil {
				t.Fatalf("write template checksum: %v", err)
			}
			return directory
		}, expectedReady: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: an installed Nuclei binary and a controlled template directory.
			t.Setenv("KALI_MCP_NUCLEI_TEMPLATES", test.prepare(t))

			// When: runtime readiness is calculated.
			status := toolStatus(func(string) bool { return true })

			// Then: Nuclei readiness includes its template installation state.
			if status["nuclei"] != test.expectedReady {
				t.Fatalf("unexpected Nuclei readiness: %v", status)
			}
		})
	}
}
