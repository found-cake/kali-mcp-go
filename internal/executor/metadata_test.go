package executor

import (
	"slices"
	"testing"
)

func TestVersionArgumentsUseToolSpecificFlags(t *testing.T) {
	// Given: tools whose version flags differ from the GNU convention.
	tests := []struct {
		tool string
		want []string
	}{
		{tool: "ffuf", want: []string{"-V"}},
		{tool: "nuclei", want: []string{"-version"}},
		{tool: "gobuster", want: []string{"version"}},
	}

	// When: execution metadata prepares each version probe.
	for _, test := range tests {
		// Then: the tool's supported flag is used.
		if got := versionArguments(test.tool); !slices.Equal(got, test.want) {
			t.Errorf("versionArguments(%q) = %v, want %v", test.tool, got, test.want)
		}
	}
}
