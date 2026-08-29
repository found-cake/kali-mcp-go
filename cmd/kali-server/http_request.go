package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
	"golang.org/x/net/http/httpguts"
)

const (
	defaultHTTPResponseBytes = 1024 * 1024
	maximumHTTPResponseBytes = 4 * 1024 * 1024
	maximumHTTPRequestBytes  = 1024 * 1024
	defaultHTTPRequestTime   = 30 * time.Second
	maximumHTTPRequestTime   = 5 * time.Minute
	maximumHTTPHeaders       = 64
	maximumHTTPRedirects     = 5
)

var requestHTTPTransport = &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSHandshakeTimeout: 5 * time.Second,
	IdleConnTimeout:     30 * time.Second,
}

func handleHTTPRequest(c fiber.Ctx) error {
	request, err := parseRequest(c, validateHTTPRequest)
	if err != nil {
		return badRequest(c, err.Error())
	}
	if err := tools.ValidateScanProfile("http-request", request.ScanOptions); err != nil {
		return badRequest(c, err.Error())
	}
	options := request.ScanOptions
	provenance, err := resolveTargetProvenance(request, apiTokenFromContext(c), time.Now().UTC())
	if err != nil {
		return badRequest(c, err.Error())
	}
	release := func() {}
	if scheduler := schedulerFromContext(c); scheduler != nil {
		release, err = scheduler.acquire(request.URL, 1)
		if err != nil {
			return scanPreparationError(c, err)
		}
	}
	defer release()

	timeout := httpRequestTimeout(request.Timeout)
	method := normalizedHTTPMethod(request.Method)
	startedAt := time.Now().UTC()
	requestCount := 1
	result := &executor.Result{
		CallID:       callIDFromContext(c),
		ReturnCode:   -1,
		HTTPRequests: &requestCount,
		StartedAt:    startedAt,
		Tool:         "http-request",
		ToolVersion:  runtime.Version(),
		ArgvRedacted: []string{method, request.URL},
		Timeout:      timeout,
		Target:       provenance,
		Policy:       options,
	}
	execContext, cancel := context.WithTimeout(c.Context(), timeout)
	defer cancel()
	httpRequest, err := newHTTPRequest(execContext, request, method)
	if err != nil {
		result.Stderr = err.Error()
		result.FailureCode = "http_request_invalid"
		return sendHTTPRequestResult(c, result, request)
	}
	response, err := newHTTPClient(request).Do(httpRequest)
	if err != nil {
		result.Stderr = err.Error()
		result.FailureCode = "http_request_failed"
		result.TimedOut = errors.Is(execContext.Err(), context.DeadlineExceeded)
		result.Cancelled = errors.Is(execContext.Err(), context.Canceled)
		return sendHTTPRequestResult(c, result, request)
	}
	defer response.Body.Close()
	retained, truncated, err := readHTTPBody(response.Body, responseByteLimit(request.MaxResponseBytes))
	result.HTTPResponse = &dto.HTTPResponseMetadata{
		StatusCode:    response.StatusCode,
		Headers:       response.Header.Clone(),
		FinalURL:      response.Request.URL.String(),
		ContentLength: response.ContentLength,
		BodyBytes:     len(retained),
		BodyTruncated: truncated,
	}
	if err != nil {
		result.Stderr = err.Error()
		result.FailureCode = "http_response_read_failed"
		return sendHTTPRequestResult(c, result, request)
	}
	if utf8.Valid(retained) {
		result.Stdout = string(retained)
		result.HTTPResponse.BodyEncoding = "utf-8"
	} else {
		result.Stdout = base64.StdEncoding.EncodeToString(retained)
		result.HTTPResponse.BodyEncoding = "base64"
	}
	result.ReturnCode = 0
	return sendHTTPRequestResult(c, result, request)
}

func validateHTTPRequest(request dto.HTTPRequest) error {
	parsed, err := url.Parse(request.URL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("url must be an HTTP or HTTPS URL without userinfo")
	}
	if _, err := parseHTTPMethod(request.Method); err != nil {
		return err
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

func newHTTPClient(request dto.HTTPRequest) *http.Client {
	initialOrigin, _ := webOrigin(request.URL)
	return &http.Client{
		Transport: requestHTTPTransport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if !request.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > maximumHTTPRedirects {
				return fmt.Errorf("redirect limit exceeded")
			}
			nextOrigin, ok := webOrigin(next.URL.String())
			if !ok || nextOrigin != initialOrigin {
				return fmt.Errorf("cross-origin redirect rejected")
			}
			return nil
		},
	}
}

func readHTTPBody(body io.Reader, limit int) ([]byte, bool, error) {
	payload, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return nil, false, fmt.Errorf("read HTTP response: %w", err)
	}
	if len(payload) <= limit {
		return payload, false, nil
	}
	return payload[:limit], true, nil
}

func responseByteLimit(requested int) int {
	if requested == 0 {
		return defaultHTTPResponseBytes
	}
	return requested
}

func httpRequestTimeout(seconds int) time.Duration {
	if seconds == 0 {
		return defaultHTTPRequestTime
	}
	return time.Duration(seconds) * time.Second
}

func sendHTTPRequestResult(c fiber.Ctx, result *executor.Result, request dto.HTTPRequest) error {
	result.Duration = time.Since(result.StartedAt)
	if result.HTTPResponse != nil {
		result.Progress = &dto.ProgressMetadata{
			ObservedOutputItems: 1,
			LastObservedOutput:  fmt.Sprintf("HTTP %d", result.HTTPResponse.StatusCode),
			Checkpoint:          "response-1",
		}
	}
	result.FinalizeProgress()
	protectResult(artifactStoreFromContext(c), result, request)
	return c.JSON(toAPIResult(result))
}
