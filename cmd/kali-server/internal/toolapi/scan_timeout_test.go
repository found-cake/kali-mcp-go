package toolapi

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestPrepareScanExecution_preserves_explicit_timeout_when_request_budget_is_shorter(t *testing.T) {
	// Given: an explicit two-minute timeout and a forty-second request-budget estimate.
	app := fiber.New()
	var effectiveTimeout time.Duration
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.FFUFRequest{
			ScanOptions: dto.ScanOptions{MaxRequests: 200, RateLimit: 5},
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

func TestPrepareScanExecution_adds_startup_grace_to_derived_request_budget(t *testing.T) {
	// Given: an omitted timeout and a forty-second FFUF request-budget estimate.
	app := fiber.New()
	var planTimeout time.Duration
	var planning *dto.TimeoutPlanning
	app.Get("/prepare", func(c fiber.Ctx) error {
		plan, err := prepareScanExecution(c, dto.FFUFRequest{
			ScanOptions: dto.ScanOptions{MaxRequests: 200, RateLimit: 5},
			URL:         "https://example.com/FUZZ",
		}, []string{"ffuf", "-u", "https://example.com/FUZZ"})
		if err != nil {
			return err
		}
		defer plan.release()
		planTimeout = plan.timeout
		planning = plan.timeoutPlanning
		return c.SendStatus(fiber.StatusNoContent)
	})

	// When: the execution plan derives its timeout from the request budget.
	request, err := http.NewRequest(http.MethodGet, "/prepare", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	defer response.Body.Close()

	// Then: FFUF gets five seconds of startup grace and the estimate remains non-authoritative.
	if response.StatusCode != fiber.StatusNoContent || planTimeout != 45*time.Second {
		t.Fatalf("unexpected derived timeout: status=%d timeout=%s", response.StatusCode, planTimeout)
	}
	if planning == nil || planning.Source != dto.TimeoutSourceRequestBudget || planning.RequestBudgetEstimateMS != 40000 || planning.StartupGraceMS != 5000 || planning.MaxRequestsHardLimit {
		t.Fatalf("unexpected timeout planning metadata: %+v", planning)
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
