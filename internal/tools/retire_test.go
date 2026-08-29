package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestPrepareRetireDownloadsPublicBundlesAndCleansWorkspace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/app.js" {
			_, _ = w.Write([]byte("window.appVersion = '1.0.0';"))
			return
		}
		_, _ = w.Write([]byte(`<html><script src="/app.js"></script><script>window.inline = true;</script></html>`))
	}))
	defer server.Close()

	plan, err := PrepareRetire(context.Background(), dto.RetireRequest{URL: server.URL})
	if err != nil {
		t.Fatalf("prepare retire scan: %v", err)
	}
	workspace := plan.tempDir
	files, err := filepath.Glob(filepath.Join(workspace, "*.js"))
	if err != nil {
		t.Fatalf("list downloaded scripts: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected two JavaScript files, got %v", files)
	}
	args := strings.Join(plan.Args(), " ")
	if !strings.Contains(args, "--path "+workspace) {
		t.Fatalf("expected temporary workspace in args: %s", args)
	}
	plan.Cleanup()
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatalf("expected workspace cleanup, got %v", err)
	}
}
