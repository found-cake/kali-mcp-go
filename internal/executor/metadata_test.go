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
		{tool: "gobuster", want: []string{"--version"}},
		{tool: "john", want: []string{"--list=build-info"}},
		{tool: "enum4linux", want: []string{"-h"}},
	}

	// When: execution metadata prepares each version probe.
	for _, test := range tests {
		// Then: the tool's supported flag is used.
		if got := versionArguments(test.tool); !slices.Equal(got, test.want) {
			t.Errorf("versionArguments(%q) = %v, want %v", test.tool, got, test.want)
		}
	}
}

func TestCommandTool_unwraps_john_from_clean_environment(t *testing.T) {
	// Given: the John launcher wrapped by env for an isolated HOME.
	args := []string{"-i", "HOME=/tmp/john", "john", "--format=Raw-MD5", "/tmp/hash"}

	// When: execution metadata identifies the actual scanner.
	got := commandTool("env", args)

	// Then: the wrapper does not replace the reported tool identity.
	if got != "john" {
		t.Fatalf("command tool = %q, want john", got)
	}
}

func TestVersionLine_skips_tool_warnings_and_banners(t *testing.T) {
	// Given: real output shapes whose first line is not the version.
	tests := []struct {
		name   string
		tool   string
		output string
		want   string
	}{
		{name: "john home notice", tool: "john", output: "Created directory: /tmp/.john\nVersion: 1.9.0-jumbo", want: "Version: 1.9.0-jumbo"},
		{name: "tshark root warning", tool: "tshark", output: "Running as user root. This could be dangerous.\nTShark (Wireshark) 4.6.6.", want: "TShark (Wireshark) 4.6.6."},
		{name: "wpscan banner", tool: "wpscan", output: "________________\nVersion 3.8.28\n________________\nCurrent Version: 3.8.28", want: "Current Version: 3.8.28"},
		{name: "enum4linux help", tool: "enum4linux", output: "enum4linux v0.9.1 (http://labs.portcullis.co.uk/application/enum4linux/)\nCopyright", want: "enum4linux v0.9.1 (http://labs.portcullis.co.uk/application/enum4linux/)"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When: metadata selects one line from the combined output.
			got := versionLine(test.tool, test.output)

			// Then: the stable tool-specific version line is returned.
			if got != test.want {
				t.Fatalf("version line = %q, want %q", got, test.want)
			}
		})
	}
}
