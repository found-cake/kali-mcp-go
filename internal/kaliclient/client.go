package kaliclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultTimeout = 300 * time.Second

type Client struct {
	base string
	http *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: timeout},
	}
}
func (c *Client) Post(ctx context.Context, endpoint string, body any) (*dto.ToolResult, error) {
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

	var result dto.ToolResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}
func (c *Client) Stream(ctx context.Context, body any) (*dto.ToolResult, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/command/stream",
		bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}
	defer resp.Body.Close()

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
		var ev dto.StreamEvent
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if ev.Error != "" {
			return nil, fmt.Errorf("server: %s", ev.Error)
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

	return &dto.ToolResult{
		Stdout:     join(stdoutLines),
		Stderr:     join(stderrLines),
		ReturnCode: returnCode,
		TimedOut:   timedOut,
	}, nil
}
func (c *Client) Health(ctx context.Context) (*dto.HealthResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/health", nil)
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
