package toolapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
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
			return httpapi.BadRequest(c, err.Error())
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
	if err := targeting.AttachResolution("secret", &result, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}

	// When: Nmap supplies only the selected candidate context.
	request := dto.NmapRequest{ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext}}
	normalized, err := targeting.ApplyContext("secret", request, now)
	if err != nil {
		t.Fatalf("apply target context: %v", err)
	}
	provenance, err := targeting.ResolveProvenance(normalized, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the network form is explicit, verified, and tied to the original target.
	if normalized.Target != "192.168.65.254" || normalized.Ports != "3000" {
		t.Fatalf("unexpected network target: %s", normalized.Target)
	}
	if !provenance.Verified || provenance.Original != result.OriginalTarget || provenance.Selected != normalized.Target {
		t.Fatalf("unexpected provenance: %+v", provenance)
	}
	if provenance.Scope != dto.TargetScopeDockerHost || provenance.ContextExpiresAt != result.ReceiptExpiresAt || provenance.ExpiresInSeconds != int64((10*time.Minute)/time.Second) {
		t.Fatalf("missing context lifetime provenance: %+v", provenance)
	}
}

func TestTargetContextBindsNetworkToolPorts(t *testing.T) {
	now := time.Date(2026, time.September, 4, 1, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://192.168.65.254:3000/", NetworkTarget: "192.168.65.254",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}
	context := result.Candidates[0].TargetContext

	t.Run("Hydra receives signed port", func(t *testing.T) {
		request := dto.HydraRequest{ScanOptions: dto.ScanOptions{TargetContext: context}}
		normalized, err := targeting.ApplyContext("secret", request, now)
		if err != nil || normalized.Port != 3000 {
			t.Fatalf("Hydra port not bound: request=%+v err=%v", normalized, err)
		}
	})

	t.Run("Metasploit receives signed RPORT", func(t *testing.T) {
		request := dto.MetasploitRequest{ScanOptions: dto.ScanOptions{TargetContext: context}}
		normalized, err := targeting.ApplyContext("secret", request, now)
		if err != nil || normalized.Options["RPORT"] != "3000" {
			t.Fatalf("Metasploit RPORT not bound: request=%+v err=%v", normalized, err)
		}
	})

	for _, test := range []struct {
		name      string
		normalize func() (string, error)
	}{
		{name: "Nuclei host form retains port", normalize: func() (string, error) {
			request, err := targeting.ApplyContext("secret", dto.NucleiRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "192.168.65.254",
			}, now)
			return request.Target, err
		}},
		{name: "WhatWeb host form retains port", normalize: func() (string, error) {
			request, err := targeting.ApplyContext("secret", dto.WhatWebRequest{
				ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "192.168.65.254",
			}, now)
			return request.Target, err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := test.normalize()
			if err != nil || target != "http://192.168.65.254:3000/" {
				t.Fatalf("URL-or-host target lost signed port: target=%q err=%v", target, err)
			}
		})
	}

	for _, test := range []struct {
		name    string
		request any
		message string
	}{
		{name: "Nmap mismatched port", request: dto.NmapRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Ports: "80"}, message: "port"},
		{name: "Hydra mismatched port", request: dto.HydraRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Port: 22}, message: "port"},
		{name: "Metasploit mismatched port", request: dto.MetasploitRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Options: map[string]string{"RPORT": "8080"}}, message: "port"},
		{name: "Metasploit virtual host", request: dto.MetasploitRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Options: map[string]string{"VHOST": "foreign.test"}}, message: "VHOST"},
		{name: "Metasploit proxy", request: dto.MetasploitRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Options: map[string]string{"Proxies": "http:foreign.test:8080"}}, message: "Proxies"},
		{name: "Gobuster DNS with port context", request: dto.GobusterRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Mode: "dns"}, message: "port"},
		{name: "Enum4linux with port context", request: dto.Enum4linuxRequest{ScanOptions: dto.ScanOptions{TargetContext: context}}, message: "port"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var err error
			switch request := test.request.(type) {
			case dto.NmapRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			case dto.HydraRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			case dto.MetasploitRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			case dto.GobusterRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			case dto.Enum4linuxRequest:
				_, err = targeting.ApplyContext("secret", request, now)
			}
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("mismatched port accepted: %v", err)
			}
		})
	}
}

func TestTargetContextRejectsMetasploitVirtualHostWithoutPort(t *testing.T) {
	now := time.Date(2026, time.September, 4, 1, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "host.docker.internal",
		Candidates: []dto.TargetCandidate{{
			NetworkTarget: "host.docker.internal", Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(time.Minute)); err != nil {
		t.Fatalf("attach target context: %v", err)
	}

	for _, option := range []string{"VHOST", "Proxies"} {
		_, err := targeting.ApplyContext("secret", dto.MetasploitRequest{
			ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext},
			Options:     map[string]string{option: "foreign.test"},
		}, now)
		if err == nil || !strings.Contains(err.Error(), option) {
			t.Fatalf("zero-port context accepted %s override: %v", option, err)
		}
	}
}

func TestTargetContextWarnsWhenExpiryIsNear(t *testing.T) {
	// Given: a verified target context with thirty seconds remaining.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget: "http://127.0.0.1:3000/",
		Candidates: []dto.TargetCandidate{{
			BrowserTarget: "http://host.docker.internal:3000/", NetworkTarget: "host.docker.internal",
			Port: 3000, Scope: dto.TargetScopeDockerHost, Selectable: true,
		}},
	}
	if err := targeting.AttachResolution("secret", &result, now.Add(30*time.Second)); err != nil {
		t.Fatalf("attach target contexts: %v", err)
	}
	request := dto.NmapRequest{Target: "host.docker.internal", ScanOptions: dto.ScanOptions{TargetContext: result.Candidates[0].TargetContext}}

	// When: scan provenance is resolved immediately before execution.
	provenance, err := targeting.ResolveProvenance(request, "secret", now)
	if err != nil {
		t.Fatalf("resolve provenance: %v", err)
	}

	// Then: the result exposes the remaining lifetime and a machine-readable warning state.
	if !provenance.ExpiringSoon || provenance.ExpiresInSeconds != 30 || len(targeting.Warnings(request, provenance)) == 0 {
		t.Fatalf("missing expiry warning metadata: %+v", provenance)
	}
}

func TestResolutionLifetimeRejectsExcessiveValidity(t *testing.T) {
	// Given: a requested context lifetime above the server maximum.
	// When: the bounded lifetime is parsed.
	_, err := targeting.Lifetime(3601)

	// Then: the resolver rejects the oversized validity window.
	if err == nil {
		t.Fatal("expected excessive target context lifetime to be rejected")
	}
}
