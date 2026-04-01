// Package kaliclient provides an HTTP client for the kali-server API.
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
)

const defaultTimeout = 300 * time.Second

// Result mirrors executor.Result for JSON unmarshalling.
type Result struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ReturnCode int    `json:"return_code"`
	TimedOut   bool   `json:"timed_out"`
}

// Format returns merged output text suitable for MCP tool results.
func (r *Result) Format() string {
	var sb strings.Builder
	if r.Stdout != "" {
		sb.WriteString(r.Stdout)
	}
	if r.Stderr != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n[stderr]\n")
		}
		sb.WriteString(r.Stderr)
	}
	if r.TimedOut {
		sb.WriteString("\n\n[WARNING: timed out — partial results above]")
	}
	if sb.Len() == 0 {
		sb.WriteString("(no output)")
	}
	return sb.String()
}

// HealthResult is returned by GET /health.
type HealthResult struct {
	Status                    string          `json:"status"`
	Message                   string          `json:"message"`
	ToolsStatus               map[string]bool `json:"tools_status"`
	AllEssentialToolsAvailable bool            `json:"all_essential_tools_available"`
}

// Client is an HTTP client for kali-server.
type Client struct {
	base string
	http *http.Client
}

// New creates a new Client targeting baseURL (e.g. "http://127.0.0.1:5000").
func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: timeout},
	}
}

// Post sends a JSON POST to endpoint and unmarshals the response into result.
func (c *Client) Post(ctx context.Context, endpoint string, body any) (*Result, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/"+strings.TrimLeft(endpoint, "/"),
		bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, body)
	}

	var result Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}

// Stream calls POST /api/command/stream and collects SSE output into a Result.
// This gives real-time stdout/stderr collection on the server side while still
// returning a complete Result to the MCP handler.
func (c *Client) Stream(ctx context.Context, body any) (*Result, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	// Use a no-timeout client for SSE (timeout is handled server-side)
	streamHTTP := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/command/stream",
		bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := streamHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}
	defer resp.Body.Close()

	type ssePayload struct {
		Stream     string `json:"stream"`
		Line       string `json:"line"`
		Done       bool   `json:"done"`
		ReturnCode int    `json:"return_code"`
		TimedOut   bool   `json:"timed_out"`
		Err        string `json:"error"`
	}

	var (
		stdoutLines []string
		stderrLines []string
		returnCode  int
		timedOut    bool
	)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		raw := scanner.Text()
		if !strings.HasPrefix(raw, "data: ") {
			continue
		}
		data := strings.TrimPrefix(raw, "data: ")
		var ev ssePayload
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if ev.Err != "" {
			return nil, fmt.Errorf("server: %s", ev.Err)
		}
		if ev.Done {
			returnCode = ev.ReturnCode
			timedOut = ev.TimedOut
			break
		}
		switch ev.Stream {
		case "stdout":
			stdoutLines = append(stdoutLines, ev.Line)
		case "stderr":
			stderrLines = append(stderrLines, ev.Line)
		}
	}

	join := func(lines []string) string {
		if len(lines) == 0 {
			return ""
		}
		return strings.Join(lines, "\n") + "\n"
	}

	return &Result{
		Stdout:     join(stdoutLines),
		Stderr:     join(stderrLines),
		ReturnCode: returnCode,
		TimedOut:   timedOut,
	}, nil
}

// Health calls GET /health.
func (c *Client) Health(ctx context.Context) (*HealthResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var h HealthResult
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}
