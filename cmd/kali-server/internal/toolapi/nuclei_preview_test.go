package toolapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestPreviewNucleiTemplatesReturnsLocalSelectionCount(t *testing.T) {
	// Given: a local Nuclei executable that lists two selected templates.
	directory := t.TempDir()
	executable := filepath.Join(directory, "nuclei")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'one.yaml\\ntwo.yaml\\n'\n"), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	t.Setenv("PATH", directory)
	request := dto.NucleiRequest{Target: "https://example.test", Tags: "exposure", DryRun: true}

	// When: the server prepares a non-network preview.
	preview, err := previewNucleiTemplates(context.Background(), request)

	// Then: the selected template count is returned without target requests.
	if err != nil {
		t.Fatalf("preview Nuclei templates: %v", err)
	}
	if preview.TemplatesMatched != 2 || preview.SelectionSource != "tags" || preview.TargetRequestsSent != 0 {
		t.Fatalf("unexpected Nuclei preview: %+v", preview)
	}
}
