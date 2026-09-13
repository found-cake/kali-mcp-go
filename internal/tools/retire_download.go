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

type scriptAsset struct {
	source string
	inline string
}

func downloadPageScripts(ctx context.Context, request dto.RetireRequest, destination string) error {
	parsedURL, err := parsePublicScriptURL(request.URL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	client := scopedHTTPClient(parsedURL, request.Headers)
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
		return fmt.Errorf("page contains no same-origin JavaScript to scan")
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
		if err := writeScript(destination, index, content); err != nil {
			return err
		}
	}
	return nil
}

func downloadExplicitScripts(ctx context.Context, request dto.RetireRequest, destination string) error {
	scriptURLs := request.ScriptURLs
	if len(scriptURLs) == 0 || len(scriptURLs) > maxScripts {
		return fmt.Errorf("script_urls must contain between 1 and %d URLs", maxScripts)
	}
	first, err := parsePublicScriptURL(scriptURLs[0])
	if err != nil {
		return fmt.Errorf("parse script URL: %w", err)
	}
	client := scopedHTTPClient(first, request.Headers)
	seen := make(map[string]bool, len(scriptURLs))
	index := 0
	for _, address := range scriptURLs {
		parsed, err := parsePublicScriptURL(address)
		if err != nil {
			return fmt.Errorf("parse script URL: %w", err)
		}
		if !sameParsedOrigin(first, parsed) {
			return fmt.Errorf("script_urls must share one origin")
		}
		if seen[parsed.String()] {
			continue
		}
		seen[parsed.String()] = true
		content, err := fetchBytes(ctx, client, parsed.String(), maxScriptBytes)
		if err != nil {
			return fmt.Errorf("fetch script %s: %w", parsed.Redacted(), err)
		}
		if err := writeScript(destination, index, content); err != nil {
			return err
		}
		index++
	}
	return nil
}

func writeScript(destination string, index int, content []byte) error {
	name := filepath.Join(destination, fmt.Sprintf("bundle-%03d.js", index))
	if err := os.WriteFile(name, content, 0o600); err != nil {
		return fmt.Errorf("write script: %w", err)
	}
	return nil
}

func fetchBytes(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	response, err := client.Do(request)
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

type headerTransport struct {
	headers http.Header
}

func (transport headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	for name, values := range transport.headers {
		for _, value := range values {
			clone.Header.Add(name, value)
		}
	}
	return http.DefaultTransport.RoundTrip(clone)
}

func scopedHTTPClient(origin *url.URL, headers map[string]string) *http.Client {
	requestHeaders := make(http.Header, len(headers))
	for name, value := range headers {
		requestHeaders.Set(name, value)
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: headerTransport{headers: requestHeaders},
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if !sameParsedOrigin(origin, request.URL) {
				return fmt.Errorf("redirect outside selected target origin")
			}
			return nil
		},
	}
}

func parsePublicScriptURL(address string) (*url.URL, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("URL must use http or https with no userinfo")
	}
	return parsed, nil
}

func sameParsedOrigin(left, right *url.URL) bool {
	return normalizedURLOrigin(left) == normalizedURLOrigin(right)
}

func normalizedURLOrigin(parsed *url.URL) string {
	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "http") {
			port = "80"
		} else {
			port = "443"
		}
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Hostname()) + ":" + port
}

func collectScripts(root *html.Node, pageURL *url.URL) []scriptAsset {
	assets := make([]scriptAsset, 0)
	seen := make(map[string]bool)
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
				if sameParsedOrigin(pageURL, resolved) && !seen[resolved.String()] {
					seen[resolved.String()] = true
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
