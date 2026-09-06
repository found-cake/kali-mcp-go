package tools

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestDirbArgsUseSilentTerminalMode(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	t.Setenv(defaultDirWordlistEnv, wordlist)

	// Given: a bounded directory discovery request.
	request := dto.DirbRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
		URL:         "https://example.test",
	}

	// When: Dirb arguments are generated.
	args, err := DirbArgs(request)
	// Then: tested-word progress is suppressed while findings remain on stdout.
	if err != nil {
		t.Fatalf("build Dirb args: %v", err)
	}
	if !slices.Contains(args, "-S") {
		t.Fatalf("Dirb silent mode is missing: %v", args)
	}
}
