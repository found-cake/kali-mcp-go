package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestToolCallTelemetryCorrelatesJSONResult(t *testing.T) {
	t.Parallel()

	// Given a server with always-on structured call telemetry.
	app := newApp("telemetry-token", false, defaultMaxConcurrentExecutions, nil)
	request, err := http.NewRequest(http.MethodPost, "/api/command", strings.NewReader(`{"command":"printf telemetry"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer telemetry-token")
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

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
	if callID == "" || result.CallID != callID {
		t.Fatalf("expected matching call IDs, header=%q result=%q", callID, result.CallID)
	}
	if result.Execution.EndedAt.Before(result.Execution.StartedAt) {
		t.Fatalf("expected ordered execution timestamps, got %+v", result.Execution)
	}
}

func TestToolCallTelemetryCorrelatesEverySSEEvent(t *testing.T) {
	t.Parallel()

	// Given a streaming tool call routed through telemetry middleware.
	app := newApp("telemetry-token", false, defaultMaxConcurrentExecutions, nil)
	request, err := http.NewRequest(http.MethodPost, "/api/command/stream", strings.NewReader(`{"command":"printf 'first\\nsecond\\n'"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(fiber.HeaderAuthorization, "Bearer telemetry-token")
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

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
	events := mustParseSSEEvents(t, string(payload))

	// Then every event and the response header use the same call ID.
	callID := response.Header.Get(dto.CallIDHeader)
	if callID == "" || len(events) != 3 {
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
