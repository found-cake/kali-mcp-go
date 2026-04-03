package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
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

func TestHandleTsharkRequiresReadFileOrInterface(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/tshark", handleTshark)

	req, err := http.NewRequest(http.MethodPost, "/tshark", strings.NewReader(`{"packet_count":"1"}`))
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
	app.Post("/tshark", handleTshark)

	req, err := http.NewRequest(http.MethodPost, "/tshark", strings.NewReader(`{"read_file":"/tmp/a.pcap","interface":"eth0"}`))
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
	app.Post("/tshark", handleTshark)

	req, err := http.NewRequest(http.MethodPost, "/tshark", strings.NewReader(`{"read_file":"/tmp/a.pcap","packet_count":"0"}`))
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

func TestHandleNmapRejectsMalformedAdditionalArgs(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Post("/nmap", handleNmap)

	body := `{"target":"127.0.0.1","additional_args":"--script \"bad"}`
	req, err := http.NewRequest(http.MethodPost, "/nmap", strings.NewReader(body))
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
