package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

type fakeStreamTicker struct {
	ch <-chan time.Time
}

func (t fakeStreamTicker) Chan() <-chan time.Time { return t.ch }
func (t fakeStreamTicker) Stop()                  {}

type failingStreamWriter struct {
	writeCalls int
	flushed    bool
}

func (w *failingStreamWriter) WriteString(string) (int, error) {
	w.writeCalls++
	return 0, fmt.Errorf("forced write failure")
}

func (w *failingStreamWriter) Flush() error {
	w.flushed = true
	return nil
}

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
		if chunk == "" {
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

func TestHandleNmapStreamRejectsMissingTarget(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nmap/stream", handleNmapStream)

	req, err := http.NewRequest(http.MethodPost, "/nmap/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "target is required") {
		t.Fatalf("expected target validation message, got %s", string(body))
	}
}

func TestHandleCommandStreamRejectsMissingCommand(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/command/stream", handleCommandStream)

	req, err := http.NewRequest(http.MethodPost, "/command/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "command is required") {
		t.Fatalf("expected command validation message, got %s", string(body))
	}
}

func TestHandleCommandStreamSuccessStreamsLinesBeforeDone(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/command/stream", handleCommandStream)

	req, err := http.NewRequest(http.MethodPost, "/command/stream", strings.NewReader(`{"command":"printf 'hello\\nworld\\n'"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("expected SSE content type, got %q", got)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))
	if len(events) != 3 {
		t.Fatalf("expected 3 SSE events, got %d (%s)", len(events), string(body))
	}
	if events[0].Stream != "stdout" || events[0].Line != "hello" {
		t.Fatalf("expected first stdout event for hello, got %+v", events[0])
	}
	if events[1].Stream != "stdout" || events[1].Line != "world" {
		t.Fatalf("expected second stdout event for world, got %+v", events[1])
	}
	if !events[2].Done {
		t.Fatalf("expected final done event, got %+v", events[2])
	}
	if events[2].ReturnCode == nil || *events[2].ReturnCode != 0 {
		t.Fatalf("expected done return_code=0, got %+v", events[2])
	}
	if events[2].TimedOut {
		t.Fatalf("expected timed_out=false, got %+v", events[2])
	}
	if events[2].Error != "" {
		t.Fatalf("expected empty done error, got %+v", events[2])
	}
}

func TestSendToolStreamStreamsStdoutAndStderrBeforeDone(t *testing.T) {
	t.Parallel()

	lines := make(chan executor.Line, 2)
	done := make(chan *executor.Result, 1)
	lines <- executor.Line{Stream: "stdout", Text: "hello"}
	lines <- executor.Line{Stream: "stderr", Text: "warn"}
	close(lines)
	done <- &executor.Result{ReturnCode: 0, Stderr: "warn\n"}
	close(done)

	app := fiber.New()
	app.Get("/stream", func(c fiber.Ctx) error {
		return sendToolStreamWithCancel(c, lines, done, nil)
	})

	req, err := http.NewRequest(http.MethodGet, "/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))
	if len(events) != 3 {
		t.Fatalf("expected 3 SSE events, got %d (%s)", len(events), string(body))
	}
	if events[0].Done || events[1].Done {
		t.Fatalf("expected non-done events before final event, got %+v", events)
	}
	if events[0].Stream != "stdout" || events[0].Line != "hello" {
		t.Fatalf("expected first stdout event, got %+v", events[0])
	}
	if events[1].Stream != "stderr" || events[1].Line != "warn" {
		t.Fatalf("expected second stderr event, got %+v", events[1])
	}
	if !events[2].Done {
		t.Fatalf("expected final done event, got %+v", events[2])
	}
	if events[2].ReturnCode == nil || *events[2].ReturnCode != 0 {
		t.Fatalf("expected done return_code=0, got %+v", events[2])
	}
	if events[2].TimedOut {
		t.Fatalf("expected timed_out=false, got %+v", events[2])
	}
	if events[2].Error != "" {
		t.Fatalf("expected empty done error after streamed stderr, got %+v", events[2])
	}
}

func TestSendToolStreamEmitsHeartbeatBeforeDone(t *testing.T) {
	t.Parallel()

	lines := make(chan executor.Line)
	done := make(chan *executor.Result, 1)
	heartbeatCh := make(chan time.Time)
	started := make(chan struct{})

	app := fiber.New()
	app.Get("/stream", func(c fiber.Ctx) error {
		close(started)
		return sendToolStreamWithTicker(c, lines, done, nil, func() streamTicker {
			return fakeStreamTicker{ch: heartbeatCh}
		})
	})

	go func() {
		<-started
		heartbeatCh <- time.Now()
		close(lines)
		done <- &executor.Result{ReturnCode: 0}
		close(done)
	}()

	req, err := http.NewRequest(http.MethodGet, "/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))
	if len(events) != 2 {
		t.Fatalf("expected 2 SSE events, got %d (%s)", len(events), string(body))
	}
	if !events[0].Heartbeat {
		t.Fatalf("expected first event to be heartbeat, got %+v", events[0])
	}
	if !events[1].Done {
		t.Fatalf("expected final done event, got %+v", events[1])
	}
	if events[1].ReturnCode == nil || *events[1].ReturnCode != 0 {
		t.Fatalf("expected done return_code=0, got %+v", events[1])
	}
}

func TestRunToolStreamUsesRequestTimeout(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/sleep/stream", func(c fiber.Ctx) error {
		return runToolStream(c, func(streamTimeoutRequest) error { return nil }, func(streamTimeoutRequest) ([]string, error) {
			return []string{"sleep", "1"}, nil
		})
	})

	req, err := http.NewRequest(http.MethodPost, "/sleep/stream", strings.NewReader(`{"timeout":1}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, fiber.TestConfig{Timeout: 4 * time.Second})
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	events := mustParseSSEEvents(t, string(body))
	last := events[len(events)-1]
	if !last.Done {
		t.Fatalf("expected final done event, got %+v", last)
	}
	if !last.TimedOut {
		t.Fatalf("expected timed_out=true, got %+v", last)
	}
	if last.ReturnCode == nil || *last.ReturnCode != -1 {
		t.Fatalf("expected return_code=-1 for timeout, got %+v", last)
	}
}

func TestRunSendToolStreamCancelsAndDrainsOnWriteError(t *testing.T) {
	t.Parallel()

	lines := make(chan executor.Line, 2)
	done := make(chan *executor.Result, 1)
	heartbeatCh := make(chan time.Time)
	writer := &failingStreamWriter{}
	canceled := make(chan struct{})
	drained := make(chan struct{})
	var cancelOnce sync.Once

	lines <- executor.Line{Stream: "stdout", Text: "hello"}

	go func() {
		runSendToolStream(writer, lines, done, func() {
			cancelOnce.Do(func() { close(canceled) })
		}, func() streamTicker {
			return fakeStreamTicker{ch: heartbeatCh}
		})
		close(drained)
	}()

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("expected cancel to be called after write failure")
	}

	close(lines)
	done <- &executor.Result{ReturnCode: 0}
	close(done)

	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("expected stream runner to return after draining lines")
	}

	if writer.writeCalls == 0 {
		t.Fatal("expected at least one write attempt")
	}
}

func TestRunSendToolStreamWritesFallbackWhenDoneClosesWithoutValue(t *testing.T) {
	t.Parallel()

	lines := make(chan executor.Line)
	done := make(chan *executor.Result)
	heartbeatCh := make(chan time.Time)
	buf := &strings.Builder{}
	writer := bufio.NewWriter(buf)

	close(lines)
	close(done)

	runSendToolStream(writer, lines, done, nil, func() streamTicker {
		return fakeStreamTicker{ch: heartbeatCh}
	})

	events := mustParseSSEEvents(t, buf.String())
	if len(events) != 1 {
		t.Fatalf("expected 1 fallback SSE event, got %d (%s)", len(events), buf.String())
	}
	if !events[0].Done {
		t.Fatalf("expected fallback done event, got %+v", events[0])
	}
	if events[0].ReturnCode == nil || *events[0].ReturnCode != -1 {
		t.Fatalf("expected fallback return_code=-1, got %+v", events[0])
	}
	if !strings.Contains(events[0].Error, "without result") {
		t.Fatalf("expected fallback error message, got %+v", events[0])
	}
}

func TestHandleNiktoStreamRejectsMissingTarget(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nikto/stream", handleNiktoStream)

	req, err := http.NewRequest(http.MethodPost, "/nikto/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "target is required") {
		t.Fatalf("expected target validation message, got %s", string(body))
	}
}

func TestHandleDirbStreamRejectsMissingURL(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/dirb/stream", handleDirbStream)

	req, err := http.NewRequest(http.MethodPost, "/dirb/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "url is required") {
		t.Fatalf("expected url validation message, got %s", string(body))
	}
}

func TestHandleWPScanStreamRejectsMissingURL(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/wpscan/stream", handleWPScanStream)

	req, err := http.NewRequest(http.MethodPost, "/wpscan/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "url is required") {
		t.Fatalf("expected url validation message, got %s", string(body))
	}
}

func TestHandleEnum4linuxStreamRejectsMissingTarget(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/enum4linux/stream", handleEnum4linuxStream)

	req, err := http.NewRequest(http.MethodPost, "/enum4linux/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "target is required") {
		t.Fatalf("expected target validation message, got %s", string(body))
	}
}

func TestHandleSQLMapStreamRejectsMissingURL(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/sqlmap/stream", handleSQLMapStream)

	req, err := http.NewRequest(http.MethodPost, "/sqlmap/stream", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "url is required") {
		t.Fatalf("expected url validation message, got %s", string(body))
	}
}

func TestHandleNmapStreamRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nmap/stream", handleNmapStream)

	req, err := http.NewRequest(http.MethodPost, "/nmap/stream", strings.NewReader(`{"target":`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "invalid request body") {
		t.Fatalf("expected bind failure message, got %s", string(body))
	}
}

func TestHandleTsharkRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/tshark/stream", handleTsharkStream)

	req, err := http.NewRequest(http.MethodPost, "/tshark/stream", strings.NewReader(`{"read_file":`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "invalid request body") {
		t.Fatalf("expected bind failure message, got %s", string(body))
	}
}

func TestHandleTsharkRequiresReadFileOrInterface(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/tshark/stream", handleTsharkStream)

	req, err := http.NewRequest(http.MethodPost, "/tshark/stream", strings.NewReader(`{"packet_count":"1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "read_file or interface is required") {
		t.Fatalf("expected source validation message, got %s", string(body))
	}
}

func TestHandleTsharkRejectsConflictingInputs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/tshark/stream", handleTsharkStream)

	req, err := http.NewRequest(http.MethodPost, "/tshark/stream", strings.NewReader(`{"read_file":"/tmp/a.pcap","interface":"eth0"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "read_file and interface cannot be used together") {
		t.Fatalf("expected conflicting source validation message, got %s", string(body))
	}
}

func TestHandleTsharkRejectsInvalidPacketCount(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/tshark/stream", handleTsharkStream)

	req, err := http.NewRequest(http.MethodPost, "/tshark/stream", strings.NewReader(`{"read_file":"/tmp/a.pcap","packet_count":"0"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(body), "packet_count must be a positive integer") {
		t.Fatalf("expected packet_count validation message, got %s", string(body))
	}
}

func TestHandleMetasploitRejectsMultilineOptionValue(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/metasploit", handleMetasploit)

	body := `{"module":"exploit/multi/handler","options":{"RHOSTS":"10.0.0.1\nsetg AutoRunScript post/multi/manage/shell_to_meterpreter"}}`
	req, err := http.NewRequest(http.MethodPost, "/metasploit", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "options must not contain line breaks") {
		t.Fatalf("expected multiline rejection message, got %s", string(respBody))
	}
}

func TestHandleHydraRejectsConflictingUsernameInputs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/hydra", handleHydra)

	body := `{"target":"127.0.0.1","service":"ssh","username":"root","username_file":"/tmp/users.txt","password":"toor"}`
	req, err := http.NewRequest(http.MethodPost, "/hydra", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "username and username_file cannot be used together") {
		t.Fatalf("expected username conflict validation message, got %s", string(respBody))
	}
}

func TestHandleHydraRejectsConflictingPasswordInputs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/hydra", handleHydra)

	body := `{"target":"127.0.0.1","service":"ssh","username":"root","password":"toor","password_file":"/tmp/passwords.txt"}`
	req, err := http.NewRequest(http.MethodPost, "/hydra", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "password and password_file cannot be used together") {
		t.Fatalf("expected password conflict validation message, got %s", string(respBody))
	}
}

func TestHandleHydraStreamRejectsMissingTarget(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/hydra/stream", handleHydraStream)

	body := `{"service":"ssh","username":"root","password":"toor"}`
	req, err := http.NewRequest(http.MethodPost, "/hydra/stream", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "target and service are required") {
		t.Fatalf("expected required-fields validation message, got %s", string(respBody))
	}
}

func TestHandleHydraStreamRejectsMissingService(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/hydra/stream", handleHydraStream)

	body := `{"target":"127.0.0.1","username":"root","password":"toor"}`
	req, err := http.NewRequest(http.MethodPost, "/hydra/stream", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "target and service are required") {
		t.Fatalf("expected required-fields validation message, got %s", string(respBody))
	}
}

func TestHandleHydraStreamRejectsConflictingUsernameInputs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/hydra/stream", handleHydraStream)

	body := `{"target":"127.0.0.1","service":"ssh","username":"root","username_file":"/tmp/users.txt","password":"toor"}`
	req, err := http.NewRequest(http.MethodPost, "/hydra/stream", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "username and username_file cannot be used together") {
		t.Fatalf("expected username conflict validation message, got %s", string(respBody))
	}
}

func TestHandleHydraStreamRejectsConflictingPasswordInputs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/hydra/stream", handleHydraStream)

	body := `{"target":"127.0.0.1","service":"ssh","username":"root","password":"toor","password_file":"/tmp/passwords.txt"}`
	req, err := http.NewRequest(http.MethodPost, "/hydra/stream", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "password and password_file cannot be used together") {
		t.Fatalf("expected password conflict validation message, got %s", string(respBody))
	}
}

func TestHandleNmapStreamRejectsMalformedAdditionalArgs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nmap/stream", handleNmapStream)

	body := `{"target":"127.0.0.1","additional_args":"--script \"bad"}`
	req, err := http.NewRequest(http.MethodPost, "/nmap/stream", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "invalid additional_args") {
		t.Fatalf("expected additional_args validation message, got %s", string(respBody))
	}
}

func TestToolStatusTracksWordlistReadinessSeparatelyFromEssentialFlagSemantics(t *testing.T) {
	dirWordlist, err := os.CreateTemp(t.TempDir(), "dir-wordlist-*.txt")
	if err != nil {
		t.Fatalf("create dir wordlist: %v", err)
	}
	defer dirWordlist.Close()

	t.Setenv("KALI_MCP_DIR_WORDLIST", dirWordlist.Name())
	t.Setenv("KALI_MCP_JOHN_WORDLIST", "/missing/john-wordlist.txt")

	status := toolStatus(func(name string) bool {
		switch name {
		case "sqlmap":
			return false
		default:
			return true
		}
	})

	if !status["gobuster"] || !status["dirb"] {
		t.Fatalf("expected gobuster and dirb to be ready when binary and default wordlist exist: %v", status)
	}
	if status["john"] {
		t.Fatalf("expected john to be unavailable when default wordlist is missing: %v", status)
	}
	if !allEssentialToolsAvailable(status) {
		t.Fatalf("expected essential flag to ignore non-essential sqlmap readiness: %v", status)
	}
}

func TestHandleHealthUsesEssentialSubsetForAggregateFlag(t *testing.T) {
	t.Setenv("KALI_MCP_DIR_WORDLIST", "/missing/dir-wordlist.txt")
	t.Setenv("KALI_MCP_JOHN_WORDLIST", "/missing/john-wordlist.txt")

	app := fiber.New()
	app.Get("/health", handleHealth)

	req, err := http.NewRequest(http.MethodGet, "/health", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	var body dto.HealthResult
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.AllEssentialToolsAvailable && (!body.ToolsStatus["gobuster"] || !body.ToolsStatus["dirb"]) {
		t.Fatalf("aggregate essential flag should not report ready when essential tools are not ready: %+v", body)
	}
	if body.Status != "degraded" {
		t.Fatalf("expected degraded status when essential tools are missing, got %+v", body)
	}
	if body.ToolsStatus["john"] {
		t.Fatalf("expected john readiness to reflect missing default wordlist: %+v", body)
	}
}

func TestTerminalStreamErrorRemovesAlreadyStreamedStderrPrefix(t *testing.T) {
	t.Parallel()

	result := &executor.Result{ReturnCode: 1, Stderr: "warn line\n\nwait: process interrupted"}

	got := terminalStreamError(result, "warn line\n")
	want := "wait: process interrupted"
	if got != want {
		t.Fatalf("expected terminal error %q, got %q", want, got)
	}
}

func TestRegisterRoutesRejectsMissingBearerToken(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	registerRoutes(app, "secret-token")

	req, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(`{"target":"127.0.0.1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}
}

func TestRegisterRoutesAcceptsValidBearerToken(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	registerRoutes(app, "secret-token")

	req, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected status %d after auth passed, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
}

func TestRegisterRoutesRejectsInvalidBearerToken(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	registerRoutes(app, "secret-token")

	req, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(`{"target":"127.0.0.1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}
}

func TestNewAppWithDebugLogsRequests(t *testing.T) {
	t.Parallel()

	var lines []string
	app := newApp("secret-token", true, func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})

	req, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(`{"target":"127.0.0.1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}
	if len(lines) != 1 {
		t.Fatalf("expected one debug log line, got %d (%v)", len(lines), lines)
	}
	if !strings.Contains(lines[0], "POST /api/tools/nmap/stream -> 401 (") {
		t.Fatalf("expected method/path/status log line, got %q", lines[0])
	}
}

func TestNewAppWithoutDebugDoesNotLogRequests(t *testing.T) {
	t.Parallel()

	logged := false
	app := newApp("secret-token", false, func(string, ...any) {
		logged = true
	})

	req, err := http.NewRequest(http.MethodPost, "/api/tools/nmap/stream", strings.NewReader(`{"target":"127.0.0.1"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}
	if logged {
		t.Fatal("expected debug logging to stay disabled")
	}
}

func TestRunToolRejectsEmptyCommandSlice(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/empty", func(c fiber.Ctx) error {
		return runTool(c, func(_ struct{}) error { return nil }, func(_ struct{}) ([]string, error) {
			return []string{}, nil
		})
	})

	req, err := http.NewRequest(http.MethodPost, "/empty", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", fiber.StatusInternalServerError, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "internal error: no command generated") {
		t.Fatalf("expected empty command error, got %s", string(respBody))
	}
}

func TestRunToolStreamRejectsEmptyCommandSlice(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/empty/stream", func(c fiber.Ctx) error {
		return runToolStream(c, func(streamTimeoutRequest) error { return nil }, func(streamTimeoutRequest) ([]string, error) {
			return []string{}, nil
		})
	})

	req, err := http.NewRequest(http.MethodPost, "/empty/stream", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", fiber.StatusInternalServerError, resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "internal error: no command generated") {
		t.Fatalf("expected empty command error, got %s", string(respBody))
	}
}
