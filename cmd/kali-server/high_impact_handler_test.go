package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestHydraDryRunRequiresContextAndRedactsPreview(t *testing.T) {
	context := signedHighImpactContext(t)
	request := dto.HydraRequest{
		ScanOptions: dto.ScanOptions{TargetContext: context},
		Service:     "ssh", Username: "root", Password: "secret-password", DryRun: true,
	}
	result := postHighImpactRequest(t, "/hydra", handleHydra, request)
	if !result.Success || !result.Execution.DryRun || result.Target == nil || !result.Target.Verified || result.Target.Selected != "192.0.2.10" {
		t.Fatalf("dry run lacks verified target evidence: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	if strings.Contains(string(encoded), "secret-password") || !strings.Contains(result.Stdout, "tool was not executed") {
		t.Fatalf("dry run leaked a secret or executed unexpectedly: %s", encoded)
	}
}

func TestMetasploitDryRunPinsContextTargetWithoutExposingRCFile(t *testing.T) {
	request := dto.MetasploitRequest{
		ScanOptions: dto.ScanOptions{TargetContext: signedHighImpactContext(t)},
		Module:      "auxiliary/scanner/http/title", Options: map[string]string{"RPORT": "3000"}, DryRun: true,
	}
	result := postHighImpactRequest(t, "/metasploit", handleMetasploit, request)
	if !result.Success || result.Target == nil || result.Target.Selected != "192.0.2.10" {
		t.Fatalf("Metasploit preview lacks pinned target: %+v", result)
	}
	if len(result.Execution.ArgvRedacted) < 3 || result.Execution.ArgvRedacted[2] != "[REDACTED]" {
		t.Fatalf("Metasploit preview exposed its temporary RC file: %+v", result.Execution.ArgvRedacted)
	}
}

func TestMetasploitRejectsTargetOverrideInOptions(t *testing.T) {
	err := validateMetasploitRequest(dto.MetasploitRequest{
		Module: "auxiliary/scanner/http/title", Target: "192.0.2.10",
		Options: map[string]string{"rhosts": "198.51.100.20"},
	})
	if err == nil || !strings.Contains(err.Error(), "set from target_context") {
		t.Fatalf("expected target override rejection, got %v", err)
	}
}

func TestMetasploitRequiresSelectedTarget(t *testing.T) {
	err := validateMetasploitRequest(dto.MetasploitRequest{Module: "auxiliary/scanner/http/title"})
	if err == nil || err.Error() != "target is required" {
		t.Fatalf("expected selected target requirement, got %v", err)
	}
}

func signedHighImpactContext(t *testing.T) string {
	t.Helper()
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.0.2.10:3000/", NetworkTarget: "192.0.2.10", Port: 3000,
			Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("test-secret", &result, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}
	return result.Candidates[0].TargetContext
}

func postHighImpactRequest[T any](t *testing.T, path string, handler fiber.Handler, body T) dto.ToolResult {
	t.Helper()
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals(apiTokenLocalKey, "test-secret")
		return c.Next()
	})
	app.Post(path, handler)
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("call handler: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != fiber.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	var result dto.ToolResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return result
}
