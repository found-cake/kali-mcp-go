package httpexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"golang.org/x/net/http/httpguts"
)

func Validate(request dto.HTTPRequest) error {
	parsed, err := url.Parse(request.URL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("url must be an HTTP or HTTPS URL without userinfo")
	}
	method, err := parseHTTPMethod(request.Method)
	if err != nil {
		return err
	}
	if request.Profile == dto.ProfileSafeRecon && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		return fmt.Errorf("safe-recon only permits GET, HEAD, or OPTIONS; use explicit-custom for state-changing methods")
	}
	if len(request.Headers) > maximumHTTPHeaders {
		return fmt.Errorf("headers cannot contain more than %d entries", maximumHTTPHeaders)
	}
	for name, value := range request.Headers {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("headers contain an invalid name or value")
		}
	}
	if request.Body != "" && len(request.JSONBody) > 0 {
		return fmt.Errorf("body and json_body cannot be used together")
	}
	if len(request.Body) > maximumHTTPRequestBytes || len(request.JSONBody) > maximumHTTPRequestBytes {
		return fmt.Errorf("request body exceeds %d bytes", maximumHTTPRequestBytes)
	}
	if len(request.JSONBody) > 0 && !json.Valid(request.JSONBody) {
		return fmt.Errorf("json_body must contain valid JSON")
	}
	if request.MaxResponseBytes < 0 || request.MaxResponseBytes > maximumHTTPResponseBytes {
		return fmt.Errorf("max_response_bytes must be between 1 and %d", maximumHTTPResponseBytes)
	}
	if request.Timeout < 0 || time.Duration(request.Timeout)*time.Second > maximumHTTPRequestTime {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if request.MaxRequests != 0 || request.RateLimit != 0 || request.Concurrency != 0 || request.HealthURL != "" || request.Max5xxResponses != 0 {
		return fmt.Errorf("single HTTP requests do not accept multi-request scan controls")
	}
	return nil
}

func parseHTTPMethod(method string) (string, error) {
	normalized := normalizedHTTPMethod(method)
	switch normalized {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return normalized, nil
	default:
		return "", fmt.Errorf("method must be GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS")
	}
}

func normalizedHTTPMethod(method string) string {
	if strings.TrimSpace(method) == "" {
		return http.MethodGet
	}
	return strings.ToUpper(strings.TrimSpace(method))
}

func newHTTPRequest(ctx context.Context, request dto.HTTPRequest, method string) (*http.Request, error) {
	var body io.Reader
	if len(request.JSONBody) > 0 {
		body = bytes.NewReader(request.JSONBody)
	} else if request.Body != "" {
		body = strings.NewReader(request.Body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, request.URL, body)
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	for name, value := range request.Headers {
		if strings.EqualFold(name, "Host") {
			httpRequest.Host = value
			continue
		}
		httpRequest.Header.Set(name, value)
	}
	if len(request.JSONBody) > 0 && httpRequest.Header.Get("Content-Type") == "" {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	return httpRequest, nil
}
