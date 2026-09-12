package tools

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func NucleiTemplateListArgs(request dto.NucleiRequest) ([]string, error) {
	if err := validateNucleiSafety(request); err != nil {
		return nil, err
	}
	if request.AllowUnsafe && strings.TrimSpace(request.AdditionalArgs) != "" {
		return nil, fmt.Errorf("Nuclei template preview with allow_unsafe requires selection through severity, tags, or templates instead of additional_args")
	}
	args := []string{"nuclei", "-tl", "-disable-update-check", "-silent"}
	if request.Severity != "" {
		args = append(args, "-severity", request.Severity)
	}
	if request.Tags != "" {
		args = append(args, "-tags", request.Tags)
	}
	for _, template := range request.Templates {
		args = append(args, "-t", template)
	}
	if !request.AllowUnsafe {
		args = append(args, "-etags", safeNucleiExcludedTags, "-no-interactsh")
	}
	return args, nil
}

func CountNucleiTemplateList(output string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		path := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			count++
		}
	}
	return count
}

func SummarizeNucleiTemplateList(request dto.NucleiRequest, output string) dto.NucleiPreviewMetadata {
	return dto.NucleiPreviewMetadata{
		TemplatesMatched:   CountNucleiTemplateList(output),
		SelectionSource:    NucleiSelectionSource(request),
		TargetRequestsSent: 0,
	}
}

func NucleiSelectionSource(request dto.NucleiRequest) string {
	filters := make([]string, 0, 3)
	if len(request.Templates) > 0 {
		filters = append(filters, "templates")
	}
	if strings.TrimSpace(request.Tags) != "" {
		filters = append(filters, "tags")
	}
	if strings.TrimSpace(request.Severity) != "" {
		filters = append(filters, "severity")
	}
	if len(filters) == 0 {
		return "all_safe_templates"
	}
	return strings.Join(filters, "_and_")
}
