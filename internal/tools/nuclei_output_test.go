package tools

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestNucleiArgsSeparatesFindingsFromDiagnosticOutput(t *testing.T) {
	// Given: a bounded Nuclei scan request.
	request := dto.NucleiRequest{Target: "https://example.com", Tags: "http"}

	// When: command arguments are generated.
	args, err := NucleiArgs(request)
	if err != nil {
		t.Fatalf("build nuclei args: %v", err)
	}

	// Then: stdout is restricted to color-free finding records while statistics remain enabled.
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, " -silent ") || !strings.Contains(joined, " -nc ") || !strings.Contains(joined, " -stats-json ") {
		t.Fatalf("Nuclei output channels are not separated: %v", args)
	}
}
