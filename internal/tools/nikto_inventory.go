package tools

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const niktoPluginInventorySource = "nikto -list-plugins"

var niktoPluginRiskHints = map[string][]dto.PluginRiskHint{
	"apacheusers":  {dto.PluginRiskHighRequestCount},
	"dictionary":   {dto.PluginRiskHighRequestCount},
	"httpoptions":  {dto.PluginRiskNonstandardHTTPMethods},
	"optionsbleed": {dto.PluginRiskHighRequestCount},
	"put_del_test": {dto.PluginRiskTargetStateChange},
	"shellshock":   {dto.PluginRiskActiveExploitProbe},
	"springboot":   {dto.PluginRiskLargeSensitiveResponse},
}

func InspectNiktoPlugins(ctx context.Context) (dto.ToolPluginInventory, error) {
	inventory := dto.ToolPluginInventory{
		Source:            niktoPluginInventorySource,
		RiskHintsComplete: false,
		Plugins:           []dto.ToolPluginCapability{},
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(inspectCtx, "nikto", "-list-plugins").CombinedOutput()
	if err != nil {
		return inventory, fmt.Errorf("run %s: %w", niktoPluginInventorySource, err)
	}
	inventory.Plugins = ParseNiktoPluginList(string(output))
	if len(inventory.Plugins) == 0 {
		return inventory, fmt.Errorf("%s returned no plugin inventory", niktoPluginInventorySource)
	}
	inventory.Available = true
	versionOutput, versionErr := exec.CommandContext(inspectCtx, "nikto", "-Version").CombinedOutput()
	if versionErr == nil {
		inventory.RuntimeVersion = parseNiktoVersion(string(versionOutput))
	}
	return inventory, nil
}

func ParseNiktoPluginList(output string) []dto.ToolPluginCapability {
	plugins := make([]dto.ToolPluginCapability, 0)
	current := dto.ToolPluginCapability{}
	flush := func() {
		if current.Name == "" {
			return
		}
		current.RiskHints = slices.Clone(niktoPluginRiskHints[current.Name])
		plugins = append(plugins, current)
		current = dto.ToolPluginCapability{}
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if name, found := strings.CutPrefix(line, "Plugin:"); found {
			flush()
			current.Name = strings.TrimSpace(name)
			continue
		}
		if current.Name == "" || current.Description != "" || line == "" || strings.HasPrefix(line, "Written by") || strings.HasPrefix(line, "Options:") {
			continue
		}
		current.Description = line
	}
	flush()
	return plugins
}

func ValidateNiktoPluginSelection(selected []string, inventory dto.ToolPluginInventory) error {
	if !inventory.Available {
		return fmt.Errorf("Nikto plugin inventory is unavailable")
	}
	installed := make(map[string]bool, len(inventory.Plugins))
	for _, plugin := range inventory.Plugins {
		installed[plugin.Name] = true
	}
	for _, name := range selected {
		if !installed[name] {
			return fmt.Errorf("Nikto plugin %q is not installed; inspect get_scan_capabilities", name)
		}
	}
	return nil
}

func AttachNiktoPluginInventory(result *dto.ScanCapabilitiesResult, inventory dto.ToolPluginInventory) {
	for index := range result.Tools {
		if result.Tools[index].Tool != "nikto_scan" {
			continue
		}
		copy := inventory
		copy.Plugins = slices.Clone(inventory.Plugins)
		for pluginIndex := range copy.Plugins {
			copy.Plugins[pluginIndex].RiskHints = slices.Clone(copy.Plugins[pluginIndex].RiskHints)
		}
		result.Tools[index].PluginInventory = &copy
		return
	}
}

func parseNiktoVersion(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "nikto v") || strings.HasPrefix(lower, "nikto ") {
			return line
		}
	}
	return ""
}
