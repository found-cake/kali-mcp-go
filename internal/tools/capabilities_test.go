package tools

import (
	"os"
	"slices"
	"testing"
)

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
