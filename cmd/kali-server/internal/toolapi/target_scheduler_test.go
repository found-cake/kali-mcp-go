package toolapi

import "testing"

func TestScanWeightPreservesToolClasses(t *testing.T) {
	tests := []struct {
		name string
		tool string
		want int
	}{
		{name: "heavy scanner", tool: "nuclei", want: 3},
		{name: "medium scanner", tool: "gobuster", want: 2},
		{name: "light scanner", tool: "nmap", want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: a tool whose admission class is part of the server policy.
			// When: its scheduler weight is resolved.
			got := scanWeight(test.tool)

			// Then: the existing class remains stable after extracting the scheduler core.
			if got != test.want {
				t.Fatalf("scanWeight(%q) = %d, want %d", test.tool, got, test.want)
			}
		})
	}
}
