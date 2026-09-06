package tools

import "testing"

func TestCountNucleiTemplateListIgnoresRuntimeWarnings(t *testing.T) {
	// Given: Nuclei stdout containing an unsigned-template warning and one selected path.
	output := "[WRN] Loading 1 unsigned templates for scan. Use with caution.\n/root/.local/nuclei-templates/http/test.yaml\n"

	// When: the local selection is counted.
	count := CountNucleiTemplateList(output)

	// Then: only the template path contributes to the estimate.
	if count != 1 {
		t.Fatalf("template count=%d want=1", count)
	}
}
