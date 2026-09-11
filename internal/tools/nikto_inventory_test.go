package tools

import (
	"reflect"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestParseNiktoPluginListPreservesInventoryAndAddsRiskHints(t *testing.T) {
	output := `Plugin: headers
Checks for the presence of various HTTP headers.
Written by Example

Plugin: put_del_test
Tests whether PUT and DELETE work.
Written by Example

Plugin: custom_local
Locally installed custom plugin.
Written by Example
`

	got := ParseNiktoPluginList(output)
	want := []dto.ToolPluginCapability{
		{Name: "headers", Description: "Checks for the presence of various HTTP headers."},
		{Name: "put_del_test", Description: "Tests whether PUT and DELETE work.", RiskHints: []dto.PluginRiskHint{dto.PluginRiskTargetStateChange}},
		{Name: "custom_local", Description: "Locally installed custom plugin."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed inventory = %#v, want %#v", got, want)
	}
}

func TestValidateNiktoPluginSelectionChecksInstalledPlugins(t *testing.T) {
	inventory := dto.ToolPluginInventory{
		Available: true,
		Plugins: []dto.ToolPluginCapability{
			{Name: "headers"},
			{Name: "custom_local"},
		},
	}

	if err := ValidateNiktoPluginSelection([]string{"custom_local"}, inventory); err != nil {
		t.Fatalf("validate installed plugin: %v", err)
	}
	if err := ValidateNiktoPluginSelection([]string{"missing"}, inventory); err == nil {
		t.Fatal("uninstalled plugin was accepted")
	}
}

func TestParseNiktoVersionSupportsRuntimeOutput(t *testing.T) {
	if got := parseNiktoVersion("Nikto 2.6.0 (LW 2.5)\n"); got != "Nikto 2.6.0 (LW 2.5)" {
		t.Fatalf("parsed Nikto version = %q", got)
	}
}
