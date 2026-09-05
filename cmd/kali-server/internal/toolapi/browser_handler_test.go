package toolapi

import (
	"encoding/json"
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

func TestNewBrowserHeadersPathCreatesPrivateReadableHandoff(t *testing.T) {
	directory := t.TempDir()
	t.Setenv(browserOutputDirectoryEnv, directory)
	want := map[string]string{"Authorization": "Bearer test-token", "Cookie": "session=alpha"}

	path, err := newBrowserHeadersPath(want)
	if err != nil {
		t.Fatalf("allocate browser headers path: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read browser headers handoff: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("decode browser headers handoff: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat browser headers handoff: %v", err)
	}
	if filepath.Dir(path) != directory || info.Mode().Perm() != 0o640 {
		t.Fatalf("unexpected browser headers handoff: path=%s mode=%o", path, info.Mode().Perm())
	}
	if got["Authorization"] != want["Authorization"] || got["Cookie"] != want["Cookie"] {
		t.Fatalf("browser header handoff changed values: %#v", got)
	}
}
