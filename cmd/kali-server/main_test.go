package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestHandleNmapRejectsMissingTarget(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nmap", handleNmap)

	req, err := http.NewRequest(http.MethodPost, "/nmap", strings.NewReader("{}"))
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

func TestHandleNmapRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nmap", handleNmap)

	req, err := http.NewRequest(http.MethodPost, "/nmap", strings.NewReader(`{"target":`))
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
	app.Post("/tshark", handleTshark)

	req, err := http.NewRequest(http.MethodPost, "/tshark", strings.NewReader(`{"read_file":`))
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
