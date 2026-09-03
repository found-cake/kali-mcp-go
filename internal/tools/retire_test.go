package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"golang.org/x/net/html"
)

func TestPrepareRetireDownloadsExplicitBrowserScriptURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = w.Write([]byte("window.bundle = " + strings.TrimPrefix(request.URL.Path, "/") + ";"))
	}))
	defer server.Close()

	plan, err := PrepareRetire(context.Background(), dto.RetireRequest{
		ScriptURLs: []string{server.URL + "/main.js", server.URL + "/lazy.js"},
	})
	if err != nil {
		t.Fatalf("prepare explicit bundle scan: %v", err)
	}
	defer plan.Cleanup()
	if plan.EphemeralPath() == "" {
		t.Fatal("expected downloaded scripts to use a server workspace")
	}
	files, err := filepath.Glob(filepath.Join(plan.tempDir, "*.js"))
	if err != nil {
		t.Fatalf("list bundles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected two browser-observed bundles, got %v", files)
	}
}

func TestPrepareRetirePreservesCallerPathAsNonEphemeral(t *testing.T) {
	plan, err := PrepareRetire(context.Background(), dto.RetireRequest{Path: "/workspace/public"})
	if err != nil {
		t.Fatalf("prepare caller path: %v", err)
	}
	defer plan.Cleanup()
	if plan.EphemeralPath() != "" {
		t.Fatalf("caller path marked as server-generated: %q", plan.EphemeralPath())
	}
}

func TestCollectScriptsExcludesCrossOriginSources(t *testing.T) {
	document, err := html.Parse(strings.NewReader(`<script src="/same.js"></script><script src="https://cdn.example/other.js"></script>`))
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}
	pageURL, err := url.Parse("https://app.example/index.html")
	if err != nil {
		t.Fatalf("parse page URL: %v", err)
	}
	assets := collectScripts(document, pageURL)
	if len(assets) != 1 || assets[0].source != "https://app.example/same.js" {
		t.Fatalf("cross-origin scripts escaped target scope: %+v", assets)
	}
}

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
