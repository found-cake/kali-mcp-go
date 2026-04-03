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

func TestHandleTsharkRejectsMissingInterfaceAndReadFile(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/tshark", handleTshark)

	req, err := http.NewRequest(http.MethodPost, "/tshark", strings.NewReader("{}"))
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
	if !strings.Contains(string(body), "interface or read_file is required") {
		t.Fatalf("expected tshark validation message, got %s", string(body))
	}
}
