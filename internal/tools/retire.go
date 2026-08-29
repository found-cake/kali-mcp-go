package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"golang.org/x/net/html"
)

const (
	maxPageBytes   = 2 << 20
	maxScriptBytes = 10 << 20
	maxScripts     = 64
)

type RetirePlan struct {
	args    []string
	tempDir string
}

func PrepareRetire(ctx context.Context, request dto.RetireRequest) (*RetirePlan, error) {
	if (request.Path == "") == (request.URL == "") {
		return nil, fmt.Errorf("provide exactly one of path or url")
	}
	if request.Path != "" {
		args, err := RetireArgs(request)
		if err != nil {
			return nil, err
		}
		return &RetirePlan{args: args}, nil
	}
	tempDir, err := os.MkdirTemp("", "kali-mcp-retire-*")
	if err != nil {
		return nil, fmt.Errorf("create retire workspace: %w", err)
	}
	plan := &RetirePlan{tempDir: tempDir}
	if err := downloadPageScripts(ctx, rewriteLoopbackTarget(request.URL), tempDir); err != nil {
		plan.Cleanup()
		return nil, err
	}
	request.Path = tempDir
	plan.args, err = RetireArgs(request)
	if err != nil {
		plan.Cleanup()
		return nil, err
	}
	return plan, nil
}

func downloadPageScripts(ctx context.Context, pageURL, destination string) error {
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	page, err := fetchBytes(ctx, client, parsedURL.String(), maxPageBytes)
	if err != nil {
		return fmt.Errorf("fetch page: %w", err)
	}
	document, err := html.Parse(strings.NewReader(string(page)))
	if err != nil {
		return fmt.Errorf("parse page: %w", err)
	}
	scripts := collectScripts(document, parsedURL)
	if len(scripts) == 0 {
		return fmt.Errorf("page contains no JavaScript to scan")
	}
	if len(scripts) > maxScripts {
		scripts = scripts[:maxScripts]
	}
	for index, script := range scripts {
		content := []byte(script.inline)
		if script.source != "" {
			content, err = fetchBytes(ctx, client, script.source, maxScriptBytes)
			if err != nil {
				return fmt.Errorf("fetch script %s: %w", script.source, err)
			}
		}
		name := filepath.Join(destination, fmt.Sprintf("bundle-%03d.js", index))
		if err := os.WriteFile(name, content, 0o600); err != nil {
			return fmt.Errorf("write script: %w", err)
		}
	}
	return nil
}

func fetchBytes(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return content, nil
}

type scriptAsset struct {
	source string
	inline string
}

func collectScripts(root *html.Node, pageURL *url.URL) []scriptAsset {
	assets := make([]scriptAsset, 0)
	seen := make(map[string]struct{})
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "script" {
			for _, attribute := range node.Attr {
				if attribute.Key != "src" {
					continue
				}
				reference, err := url.Parse(attribute.Val)
				if err != nil {
					break
				}
				resolved := pageURL.ResolveReference(reference)
				if resolved.Scheme != "http" && resolved.Scheme != "https" {
					break
				}
				if _, ok := seen[resolved.String()]; !ok {
					seen[resolved.String()] = struct{}{}
					assets = append(assets, scriptAsset{source: resolved.String()})
				}
				break
			}
			if node.FirstChild != nil && node.FirstChild.Type == html.TextNode && strings.TrimSpace(node.FirstChild.Data) != "" {
				assets = append(assets, scriptAsset{inline: node.FirstChild.Data})
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return assets
}

func (p *RetirePlan) Args() []string {
	return append([]string(nil), p.args...)
}

func (p *RetirePlan) Cleanup() {
	if p != nil && p.tempDir != "" {
		_ = os.RemoveAll(p.tempDir)
	}
}
