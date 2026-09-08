package toolapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestProbeTargetHealthRejectsCrossOriginRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusFound)
	}))
	defer origin.Close()

	if err := probeTargetHealth(t.Context(), origin.URL); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("cross-origin health redirect was accepted: %v", err)
	}
}

func TestPrepareScanExecutionPreservesExplicitTimeout(t *testing.T) {
	// Given: an explicit two-minute timeout and scan-rate metadata.
	app := fiber.New()
	var effectiveTimeout time.Duration
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.FFUFRequest{
			ScanOptions: dto.ScanOptions{RateLimit: 5},
			URL:         "https://example.com/FUZZ",
			Timeout:     120,
		}, []string{"ffuf", "-u", "https://example.com/FUZZ"})
		if err != nil {
			return err
		}
		defer plan.release()
		effectiveTimeout = plan.timeout
		return c.SendStatus(fiber.StatusNoContent)
	})

	// When: the execution plan is prepared.
	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()

	// Then: the user's explicit timeout remains authoritative.
	if response.StatusCode != fiber.StatusNoContent || effectiveTimeout != 120*time.Second {
		t.Fatalf("explicit timeout was shortened: status=%d timeout=%s", response.StatusCode, effectiveTimeout)
	}
}

func TestPrepareScanExecutionUsesDefaultTimeoutWhenRequestTimeoutIsOmitted(t *testing.T) {
	// Given: an omitted timeout and scan-rate metadata.
	app := fiber.New()
	var planTimeout time.Duration
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.FFUFRequest{
			ScanOptions: dto.ScanOptions{RateLimit: 5},
			URL:         "https://example.com/FUZZ",
		}, []string{"ffuf", "-u", "https://example.com/FUZZ"})
		if err != nil {
			return err
		}
		defer plan.release()
		planTimeout = plan.timeout
		return c.SendStatus(fiber.StatusNoContent)
	})

	// When: the execution plan is prepared.
	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()

	// Then: the documented command timeout is used without deriving duration from request estimates.
	if response.StatusCode != fiber.StatusNoContent || planTimeout != dto.DefaultTimeout {
		t.Fatalf("unexpected default timeout: status=%d timeout=%s", response.StatusCode, planTimeout)
	}
}

func TestPrepareScanExecutionDoesNotEstimateNucleiDuration(t *testing.T) {
	// Given: an explicit one-minute Nuclei timeout and native rate limit.
	app := fiber.New()
	var planTimeout time.Duration
	var warnings []string
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.NucleiRequest{
			ScanOptions: dto.ScanOptions{RateLimit: 10},
			Target:      "https://example.com",
			Tags:        "http",
			Timeout:     60,
		}, []string{"nuclei", "-u", "https://example.com"})
		if err != nil {
			return err
		}
		defer plan.release()
		planTimeout = plan.timeout
		warnings = append(warnings, plan.extraWarnings...)
		return c.SendStatus(fiber.StatusNoContent)
	})

	// When: the execution plan is prepared.
	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()

	// Then: the user limit remains authoritative and no duration estimate is added.
	if response.StatusCode != fiber.StatusNoContent || planTimeout != 60*time.Second {
		t.Fatalf("explicit timeout changed: status=%d timeout=%s", response.StatusCode, planTimeout)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected duration-estimate warning: %v", warnings)
	}
}

func TestPrepareScanExecution_warns_when_nuclei_selector_is_omitted(t *testing.T) {
	// Given: a bounded Nuclei request without tags or explicit templates.
	app := fiber.New()
	var warnings []string
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.NucleiRequest{
			ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
			Target:      "https://example.com",
		}, []string{"nuclei", "-u", "https://example.com"})
		if err != nil {
			return err
		}
		defer plan.release()
		warnings = append(warnings, plan.extraWarnings...)
		return c.SendStatus(fiber.StatusNoContent)
	})

	// When: the execution plan is prepared.
	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()

	// Then: the unbounded template selection is explicit without changing the selector.
	if response.StatusCode != fiber.StatusNoContent || len(warnings) != 1 || !strings.Contains(warnings[0], "tags or templates") {
		t.Fatalf("missing Nuclei selector warning: status=%d warnings=%v", response.StatusCode, warnings)
	}
}

func TestRunToolRejectsEmptyCommandSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		handler fiber.Handler
	}{
		{
			name: "direct",
			path: "/empty",
			handler: func(c fiber.Ctx) error {
				return runTool(c, func(_ struct{}) error { return nil }, func(_ struct{}) ([]string, error) {
					return []string{}, nil
				})
			},
		},
		{
			name: "stream",
			path: "/empty/stream",
			handler: func(c fiber.Ctx) error {
				return runToolStream(c, func(streamTimeoutRequest) error { return nil }, func(streamTimeoutRequest) ([]string, error) {
					return []string{}, nil
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Given: a tool handler whose command builder returns no arguments.
			app := fiber.New()
			app.Post(test.path, test.handler)
			request, err := http.NewRequest(http.MethodPost, test.path, strings.NewReader(`{}`))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			// When: the handler attempts execution.
			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("app test: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			// Then: the empty command is rejected before executor invocation.
			if response.StatusCode != fiber.StatusInternalServerError || !strings.Contains(string(body), "internal error: no command generated") {
				t.Fatalf("unexpected response: status=%d body=%s", response.StatusCode, body)
			}
		})
	}
}
