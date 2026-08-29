package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestHandleScanCapabilitiesReturnsProfileToolCompatibility(t *testing.T) {
	// Given: the stateless capabilities endpoint.
	app := fiber.New()
	app.Get("/capabilities", handleScanCapabilities)

	// When: an orchestrator inspects compatibility before scanning.
	request, err := http.NewRequest(http.MethodGet, "/capabilities", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	defer response.Body.Close()
	var result dto.ScanCapabilitiesResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Then: the endpoint returns the same non-empty policy contract used at execution.
	if response.StatusCode != fiber.StatusOK || len(result.Profiles) == 0 || len(result.Tools) == 0 {
		t.Fatalf("unexpected capabilities response: status=%d result=%+v", response.StatusCode, result)
	}
}
