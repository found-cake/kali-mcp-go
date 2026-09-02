package toolapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewBrowserScreenshotPathCreatesGroupWritableHandoff(t *testing.T) {
	// Given: a root-owned directory that a sandboxed browser group may only traverse.
	directory := t.TempDir()
	t.Setenv(browserOutputDirectoryEnv, directory)

	// When: the server allocates the screenshot handoff file.
	path, err := newBrowserScreenshotPath()
	if err != nil {
		t.Fatalf("allocate screenshot path: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat screenshot handoff: %v", err)
	}

	// Then: the browser can write the file but cannot replace its directory entry.
	if filepath.Dir(path) != directory || info.Mode().Perm() != 0o620 {
		t.Fatalf("unexpected screenshot handoff: path=%s mode=%o", path, info.Mode().Perm())
	}
}
