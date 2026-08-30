package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestPrepareScanExecutionRequiresVerifiedContextForCredentialAttack(t *testing.T) {
	app := fiber.New()
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.HydraRequest{
			Target: "192.0.2.10", Service: "ssh", Username: "root", Password: "test",
		}, []string{"hydra", "192.0.2.10", "ssh"})
		if err != nil {
			return badRequest(c, err.Error())
		}
		defer plan.release()
		return c.SendStatus(fiber.StatusNoContent)
	})

	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("credential attack accepted an unverified direct target: status=%d", response.StatusCode)
	}
}

func TestTargetContextSelectsNetworkFormWithoutServerState(t *testing.T) {
	// Given: an explicitly resolved Docker-host candidate and a signed context.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{
			{
				BrowserTarget: "http://192.168.65.254:3000/",
				NetworkTarget: "192.168.65.254",
				Host:          "host.docker.internal",
				Port:          3000,
				Scope:         dto.TargetScopeDockerHost,
				Selectable:    true,
			},
		},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}
	if err := attachTargetContexts("secret", &result, issued); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}

	// When: Nmap supplies only the selected candidate context.
	request := dto.NmapRequest{ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext}}
	normalized, err := applyRequestTargetContext("secret", request, now)
	if err != nil {
		t.Fatalf("apply target context: %v", err)
	}
	provenance, err := resolveTargetProvenance(normalized, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the network form is explicit, verified, and tied to the original target.
	if normalized.Target != "192.168.65.254" {
		t.Fatalf("unexpected network target: %s", normalized.Target)
	}
	if !provenance.Verified || provenance.Original != result.OriginalTarget || provenance.Selected != normalized.Target {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
	if provenance.Scope != dto.TargetScopeDockerHost || provenance.ContextExpiresAt != issued.ExpiresAt || provenance.ExpiresInSeconds != int64(resolutionReceiptLifetime/time.Second) {
		t.Fatalf("missing context lifetime provenance: %+v", provenance)
	}
}

func TestTargetContextWarnsWhenExpiryIsNear(t *testing.T) {
	// Given: a verified target context with thirty seconds remaining.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	context, err := signTargetContext("secret", targetContextClaims{
		ResolutionID: "resolution-1", Original: "http://127.0.0.1:3000/",
		BrowserTarget: "http://host.docker.internal:3000/", NetworkTarget: "host.docker.internal",
		Port: 3000, Scope: dto.TargetScopeDockerHost, ExpiresAt: now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("sign target context: %v", err)
	}
	request := dto.NmapRequest{Target: "host.docker.internal", ScanOptions: dto.ScanOptions{TargetContext: context}}

	// When: scan provenance is resolved immediately before execution.
	provenance, err := resolveTargetProvenance(request, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the result exposes the remaining lifetime and a machine-readable warning state.
	if !provenance.ExpiringSoon || provenance.ExpiresInSeconds != 30 || len(targetWarnings(request, provenance)) == 0 {
		t.Fatalf("missing expiry warning metadata: %+v", provenance)
	}
}

func TestResolutionLifetimeRejectsExcessiveValidity(t *testing.T) {
	// Given: a requested context lifetime above the server maximum.
	// When: the bounded lifetime is parsed.
	_, err := resolutionLifetime(3601)

	// Then: the resolver rejects the oversized validity window.
	if err == nil {
		t.Fatal("expected excessive target context lifetime to be rejected")
	}
}
