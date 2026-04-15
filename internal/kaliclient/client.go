package kaliclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type Client struct {
	base    string
	token   string
	timeout time.Duration
	http    *http.Client
}

const requestTimeoutGrace = 5 * time.Second

func New(baseURL string, timeout time.Duration, token string) *Client {
	if timeout <= 0 {
		timeout = dto.DefaultTimeout
	}
	return &Client{
		base:    strings.TrimRight(baseURL, "/"),
		token:   strings.TrimSpace(token),
		timeout: timeout,
		http:    &http.Client{},
	}
}

func (c *Client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) timeoutForBody(body any) time.Duration {
	timeout := c.timeout
	switch req := body.(type) {
	case dto.TimeoutRequest:
		if requested := time.Duration(req.GetRequestTimeout()) * time.Second; requested > timeout {
			timeout = requested
		}
	}
	return timeout + requestTimeoutGrace
}

func (c *Client) requestContext(ctx context.Context, body any) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeoutForBody(body))
}

func (c *Client) newJSONRequest(ctx context.Context, method, endpoint string, body any, authorize bool) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		method,
		c.base+"/"+strings.TrimPrefix(endpoint, "/"),
		reader,
	)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authorize {
		c.authorize(req)
	}
	return req, nil
}

func (c *Client) Post(ctx context.Context, endpoint string, body any) (*dto.ToolResult, error) {
	reqCtx, cancel := c.requestContext(ctx, body)
	defer cancel()

	req, err := c.newJSONRequest(reqCtx, http.MethodPost, endpoint, body, true)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, respBody)
	}

	var result dto.ToolResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}

func (c *Client) Stream(ctx context.Context, endpoint string, body any) (*dto.ToolResult, error) {
	reqCtx, cancel := c.requestContext(ctx, body)
	defer cancel()

	req, err := c.newJSONRequest(reqCtx, http.MethodPost, endpoint, body, true)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, respBody)
	}

	var (
		stdoutLines []string
		stderrLines []string
		returnCode  int
		timedOut    bool
		done        bool
		finalError  string
	)

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		if !strings.HasPrefix(raw, "data: ") {
			continue
		}
		data := strings.TrimPrefix(raw, "data: ")
		var ev dto.StreamEvent
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			return nil, fmt.Errorf("stream decode event: %w", err)
		}
		if ev.Error != "" && !ev.Done {
			return nil, fmt.Errorf("server: %s", ev.Error)
		}
		if ev.Heartbeat {
			continue
		}
		if ev.Done {
			if ev.ReturnCode == nil {
				return nil, fmt.Errorf("stream done event missing return_code")
			}
			returnCode = *ev.ReturnCode
			timedOut = ev.TimedOut
			finalError = ev.Error
			done = true
			break
		}
		switch ev.Stream {
		case "stdout":
			stdoutLines = append(stdoutLines, ev.Line)
		case "stderr":
			stderrLines = append(stderrLines, ev.Line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("stream read: %w", err)
	}
	if !done {
		return nil, fmt.Errorf("stream ended without done event")
	}
	if finalError != "" {
		stderrLines = append(stderrLines, finalError)
	}

	join := func(lines []string) string {
		if len(lines) == 0 {
			return ""
		}
		return strings.Join(lines, "\n") + "\n"
	}

	return &dto.ToolResult{
		Stdout:         join(stdoutLines),
		Stderr:         join(stderrLines),
		ReturnCode:     returnCode,
		Success:        (!timedOut && returnCode == 0) || (timedOut && (len(stdoutLines) > 0 || len(stderrLines) > 0)),
		TimedOut:       timedOut,
		PartialResults: timedOut && (len(stdoutLines) > 0 || len(stderrLines) > 0),
	}, nil
}

func (c *Client) Health(ctx context.Context) (*dto.HealthResult, error) {
	reqCtx, cancel := c.requestContext(ctx, struct{}{})
	defer cancel()

	req, err := c.newJSONRequest(reqCtx, http.MethodGet, "/health", nil, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var h dto.HealthResult
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}
