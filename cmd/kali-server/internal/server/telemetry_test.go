package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestToolCallTelemetryCorrelatesJSONResult(t *testing.T) {
	t.Parallel()

	// Given a server with always-on structured call telemetry.
	app := newApp("telemetry-token", false, httpapi.DefaultMaxConcurrentExecutions, nil)
	request, err := http.NewRequest(http.MethodPost, "/api/command", strings.NewReader(`{"command":"printf telemetry"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer telemetry-token")
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	request.Header.Set(dto.CallIDHeader, "call_0123456789abcdef0123456789abcdef")

	// When a tool call completes through the JSON API.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	var result dto.ToolResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	// Then one call ID correlates the header, body, and bounded execution interval.
	callID := response.Header.Get(dto.CallIDHeader)
	if callID != "call_0123456789abcdef0123456789abcdef" || result.CallID != callID {
		t.Fatalf("expected matching call IDs, header=%q result=%q", callID, result.CallID)
	}
	if result.Execution.EndedAt.Before(result.Execution.StartedAt) {
		t.Fatalf("expected ordered execution timestamps, got %+v", result.Execution)
	}
}

func TestToolCallTelemetryCorrelatesEverySSEEvent(t *testing.T) {
	t.Parallel()

	// Given a streaming tool call routed through telemetry middleware.
	app := newApp("telemetry-token", false, httpapi.DefaultMaxConcurrentExecutions, nil)
	request, err := http.NewRequest(http.MethodPost, "/api/command/stream", strings.NewReader(`{"command":"printf 'first\\nsecond\\n'"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer telemetry-token")
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	request.Header.Set(dto.CallIDHeader, "call_0123456789abcdef0123456789abcdef")

	// When the complete SSE response is consumed.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	events := parseTelemetrySSEEvents(t, string(payload))

	// Then every event and the response header use the same call ID.
	callID := response.Header.Get(dto.CallIDHeader)
	if callID != "call_0123456789abcdef0123456789abcdef" || len(events) != 3 {
		t.Fatalf("expected call ID and three events, call_id=%q events=%d", callID, len(events))
	}
	for _, event := range events {
		if event.CallID != callID {
			t.Fatalf("expected event call ID %q, got %+v", callID, event)
		}
		if event.Progress == nil {
			t.Fatalf("expected progress on every event, got %+v", event)
		}
	}
	if events[2].Progress.Phase != dto.ProgressCompleted || events[2].Progress.ObservedOutputItems != 2 || events[2].Progress.ResumeSupported {
		t.Fatalf("unexpected final stream progress: %+v", events[2].Progress)
	}
}

func parseTelemetrySSEEvents(t *testing.T, body string) []dto.StreamEvent {
	t.Helper()

	chunks := strings.Split(strings.TrimSpace(body), "\n\n")
	events := make([]dto.StreamEvent, 0, len(chunks))
	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if !strings.HasPrefix(chunk, "data: ") {
			t.Fatalf("unexpected SSE chunk %q", chunk)
		}
		var event dto.StreamEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(chunk, "data: ")), &event); err != nil {
			t.Fatalf("decode SSE event: %v", err)
		}
		events = append(events, event)
	}
	return events
}

func TestRegisterRoutesBearerAuthentication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorization string
		body          string
		status        int
	}{
		{name: "missing token", body: `{"target":"127.0.0.1"}`, status: fiber.StatusUnauthorized},
		{name: "valid token", authorization: "Bearer secret-token", body: `{}`, status: fiber.StatusBadRequest},
		{name: "invalid token", authorization: "Bearer wrong-token", body: `{"target":"127.0.0.1"}`, status: fiber.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Given: a protected tool route and one bearer-token variant.
			app := fiber.New()
			registerRoutes(app, "secret-token", httpapi.NewExecutionLimiter(httpapi.DefaultMaxConcurrentExecutions))
			request, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(test.body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			if test.authorization != "" {
				request.Header.Set(fiber.HeaderAuthorization, test.authorization)
			}

			// When: authentication middleware handles the request.
			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("app test: %v", err)
			}
			defer response.Body.Close()

			// Then: only the valid token reaches request validation.
			if response.StatusCode != test.status {
				t.Fatalf("expected status %d, got %d", test.status, response.StatusCode)
			}
		})
	}
}

func TestNewAppDebugLogging(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		debug     bool
		lineCount int
	}{
		{name: "structured telemetry only", lineCount: 1},
		{name: "telemetry and request debug line", debug: true, lineCount: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Given: an application with captured logging output.
			var lines []string
			app := newApp("secret-token", test.debug, httpapi.DefaultMaxConcurrentExecutions, func(format string, args ...any) {
				lines = append(lines, fmt.Sprintf(format, args...))
			})
			request, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(`{"target":"127.0.0.1"}`))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			// When: an unauthorized request passes through telemetry middleware.
			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("app test: %v", err)
			}
			defer response.Body.Close()

			// Then: structured telemetry is always present and debug logging is opt-in.
			if response.StatusCode != fiber.StatusUnauthorized || len(lines) != test.lineCount {
				t.Fatalf("unexpected logging result: status=%d lines=%v", response.StatusCode, lines)
			}
			var telemetry struct {
				CallID     string `json:"call_id"`
				Operation  string `json:"operation"`
				HTTPStatus int    `json:"http_status"`
			}
			if err := json.Unmarshal([]byte(lines[0]), &telemetry); err != nil {
				t.Fatalf("decode telemetry: %v", err)
			}
			if telemetry.CallID == "" || telemetry.Operation != "nmap_scan" || telemetry.HTTPStatus != fiber.StatusUnauthorized {
				t.Fatalf("unexpected telemetry: %+v", telemetry)
			}
			if test.debug && !strings.Contains(lines[1], "POST /api/tools/nmap/stream -> 401 (") {
				t.Fatalf("unexpected debug line: %q", lines[1])
			}
		})
	}
}

func TestNewAppSetsStreamingTimeouts(t *testing.T) {
	t.Parallel()

	// Given: a server built with default runtime settings.
	app := newApp("secret-token", false, httpapi.DefaultMaxConcurrentExecutions, nil)

	// When: Fiber exposes its effective timeout configuration.
	config := app.Config()

	// Then: reads are bounded while streaming writes remain unbounded.
	if config.ReadTimeout != readTimeout || config.WriteTimeout != 0 {
		t.Fatalf("unexpected timeouts: read=%s write=%s", config.ReadTimeout, config.WriteTimeout)
	}
}
