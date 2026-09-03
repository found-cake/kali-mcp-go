package toolapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

type streamTimeoutRequest struct {
	Timeout int `json:"timeout,omitempty"`
}

func (r streamTimeoutRequest) GetRequestTimeout() int { return r.Timeout }

func mustParseSSEEvents(t *testing.T, body string) []dto.StreamEvent {
	t.Helper()

	chunks := strings.Split(strings.TrimSpace(body), "\n\n")
	events := make([]dto.StreamEvent, 0, len(chunks))
	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" || strings.HasPrefix(chunk, ":") {
			continue
		}
		if !strings.HasPrefix(chunk, "data: ") {
			t.Fatalf("unexpected SSE chunk %q", chunk)
		}
		var event dto.StreamEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(chunk, "data: ")), &event); err != nil {
			t.Fatalf("decode SSE event %q: %v", chunk, err)
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one SSE event")
	}
	return events
}

func TestHandleCommandStreamSuccessStreamsLinesBeforeDone(t *testing.T) {
	t.Parallel()

	// Given: a command that emits two output lines.
	app := fiber.New()
	app.Post("/command/stream", handleCommandStream)
	request, err := http.NewRequest(http.MethodPost, "/command/stream", strings.NewReader(`{"command":"printf 'hello\\nworld\\n'"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	// When: the streaming handler executes the command.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))

	// Then: output precedes one successful terminal event.
	if contentType := response.Header.Get(fiber.HeaderContentType); !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("expected SSE content type, got %q", contentType)
	}
	if len(events) != 3 || events[0].Stream != "stdout" || events[0].Line != "hello" || events[1].Stream != "stdout" || events[1].Line != "world" {
		t.Fatalf("unexpected stream events: %+v", events)
	}
	terminal := events[2]
	if !terminal.Done || terminal.ReturnCode == nil || *terminal.ReturnCode != 0 || terminal.TimedOut || terminal.Error != "" {
		t.Fatalf("unexpected terminal event: %+v", terminal)
	}
}

func TestSendToolStreamStreamsStdoutAndStderrBeforeDone(t *testing.T) {
	t.Parallel()

	// Given: completed executor channels with ordered stdout and stderr lines.
	lines := make(chan executor.Line, 2)
	done := make(chan *executor.Result, 1)
	lines <- executor.Line{Stream: "stdout", Text: "hello"}
	lines <- executor.Line{Stream: "stderr", Text: "warn"}
	close(lines)
	done <- &executor.Result{ReturnCode: 0, Stderr: "warn\n"}
	close(done)
	app := fiber.New()
	app.Get("/stream", func(c fiber.Ctx) error {
		return httpapi.SendToolStream(c, lines, done, nil)
	})

	// When: the channels are adapted into an HTTP stream.
	request, err := http.NewRequest(http.MethodGet, "/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))

	// Then: both lines arrive before a clean terminal event.
	if len(events) != 3 || events[0].Done || events[0].Stream != "stdout" || events[0].Line != "hello" || events[1].Done || events[1].Stream != "stderr" || events[1].Line != "warn" {
		t.Fatalf("unexpected stream events: %+v", events)
	}
	terminal := events[2]
	if !terminal.Done || terminal.ReturnCode == nil || *terminal.ReturnCode != 0 || terminal.TimedOut || terminal.Error != "" {
		t.Fatalf("unexpected terminal event: %+v", terminal)
	}
}

func TestRunToolStreamUsesRequestTimeout(t *testing.T) {
	t.Parallel()

	// Given: a one-second request timeout and a command that exceeds it.
	app := fiber.New()
	app.Post("/sleep/stream", func(c fiber.Ctx) error {
		return runToolStream(c, func(streamTimeoutRequest) error { return nil }, func(streamTimeoutRequest) ([]string, error) {
			return []string{"sleep", "1"}, nil
		})
	})
	request, err := http.NewRequest(http.MethodPost, "/sleep/stream", strings.NewReader(`{"timeout":1}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	// When: the stream runs past the request budget.
	response, err := app.Test(request, fiber.TestConfig{Timeout: 4 * time.Second})
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))

	// Then: the terminal event records a timeout return code.
	terminal := events[len(events)-1]
	if !terminal.Done || !terminal.TimedOut || terminal.ReturnCode == nil || *terminal.ReturnCode != -1 {
		t.Fatalf("unexpected terminal event: %+v", terminal)
	}
}
