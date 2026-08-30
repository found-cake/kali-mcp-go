package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
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
		CallID:             callIDFromContext(c),
		ReturnCode:         -1,
		HTTPRequests:       &requestCount,
		RequestCountSource: dto.RequestCountMeasured,
		StartedAt:          startedAt,
		Tool:               "http-request",
		ToolVersion:        runtime.Version(),
		ArgvRedacted:       []string{method, request.URL},
		Timeout:            timeout,
		Target:             provenance,
		Policy:             options,
	}
	execContext, cancel := context.WithTimeout(c.Context(), timeout)
	defer cancel()
	httpRequest, err := newHTTPRequest(execContext, request, method)
	if err != nil {
		result.Stderr = err.Error()
		result.FailureCode = "http_request_invalid"
		return sendHTTPRequestResult(c, result, request)
	}
	result.HTTPRequest = summarizeHTTPRequest(httpRequest, request)
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
	isUTF8 := utf8.Valid(retained)
	safeBody := retained
	sensitiveJSON := false
	if isUTF8 {
		safeBody, sensitiveJSON = tools.RedactSensitiveJSON(retained)
	}
	result.HTTPResponse.Summary = summarizeHTTPResponse(httpResponseSummaryInput{
		RetainedBody: retained, SafeBody: safeBody, Headers: response.Header,
		Secrets: tools.RequestSecrets(request), UTF8: isUTF8, SensitiveJSON: sensitiveJSON,
	})
	if isUTF8 {
		result.Stdout = string(safeBody)
		result.HTTPResponse.BodyEncoding = "utf-8"
	} else {
		result.Stdout = base64.StdEncoding.EncodeToString(retained)
		result.HTTPResponse.BodyEncoding = "base64"
	}
	result.ReturnCode = 0
	return sendHTTPRequestResult(c, result, request)
}

func summarizeHTTPRequest(httpRequest *http.Request, request dto.HTTPRequest) *dto.HTTPRequestMetadata {
	payload := request.JSONBody
	if len(payload) == 0 {
		payload = []byte(request.Body)
	}
	digest := ""
	if len(payload) > 0 {
		sum := sha256.Sum256(payload)
		digest = hex.EncodeToString(sum[:])
	}
	return &dto.HTTPRequestMetadata{
		Method: httpRequest.Method, URL: httpRequest.URL.String(), Host: httpRequest.Host,
		Headers: httpRequest.Header.Clone(), ContentType: httpRequest.Header.Get("Content-Type"),
		BodyBytes: len(payload), BodySHA256: digest, FollowRedirects: request.FollowRedirects,
	}
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
