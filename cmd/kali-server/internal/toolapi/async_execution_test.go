package toolapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/admission"
	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/jobs"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

type asyncExecutionRequest struct {
	dto.ScanOptions
	Timeout int  `json:"timeout,omitempty"`
	DryRun  bool `json:"dry_run,omitempty"`
}

func (r asyncExecutionRequest) GetRequestTimeout() int { return r.Timeout }
func (r asyncExecutionRequest) GetDryRun() bool        { return r.DryRun }

func TestRunToolStreamReturnsPendingJobWithoutWaitingForProcess(t *testing.T) {
	// Given: a streaming execution route backed by the real job, scheduler, and artifact stores.
	jobStore := jobs.New(t.Context())
	artifacts, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() {
		jobStore.Close()
		if err := artifacts.Close(); err != nil {
			t.Errorf("close artifact store: %v", err)
		}
	})
	app := fiber.New()
	app.Use(httpapi.CallTelemetryMiddleware(nil))
	app.Use(httpapi.JobStoreMiddleware(jobStore))
	app.Use(httpapi.TargetSchedulerMiddleware(admission.NewScheduler(3, 3)))
	app.Use(httpapi.ArtifactStoreMiddleware(artifacts))
	limiter := httpapi.NewExecutionLimiter(1)
	app.Post("/scan", httpapi.WithExecutionLimit(limiter, httpapi.WithCallCancellation(func(c fiber.Ctx) error {
		return runToolStream(c, func(asyncExecutionRequest) error { return nil }, func(asyncExecutionRequest) ([]string, error) {
			return []string{"nmap", "--version"}, nil
		})
	})))
	request, err := http.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	request.Header.Set("X-Kali-MCP-Async", "true")

	// When: the asynchronous scan starts through the HTTP execution boundary.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("start async scan: %v", err)
	}
	defer response.Body.Close()
	var job dto.JobResponse
	if err := json.NewDecoder(response.Body).Decode(&job); err != nil {
		t.Fatalf("decode async response: %v", err)
	}

	// Then: the request returns HTTP 202 with a pending job and direct pending data.
	if response.StatusCode != http.StatusAccepted || job.Status != dto.JobPending || job.JobID == "" {
		t.Fatalf("unexpected async response: http=%d body=%+v", response.StatusCode, job)
	}
	var pending dto.JobPendingData
	if err := json.Unmarshal(job.Data, &pending); err != nil {
		t.Fatalf("decode pending data: %v", err)
	}
	if pending.CallID == "" || pending.Tool != "nmap" {
		t.Fatalf("unexpected pending data: %+v", pending)
	}
}

func TestRunToolStreamRejectsAsyncDryRun(t *testing.T) {
	// Given: a request that combines immediate local preview with background execution.
	app := fiber.New()
	app.Use(httpapi.CallTelemetryMiddleware(nil))
	app.Post("/scan", func(c fiber.Ctx) error {
		return runToolStream(c, func(asyncExecutionRequest) error { return nil }, func(asyncExecutionRequest) ([]string, error) {
			return []string{"nuclei", "-version"}, nil
		})
	})
	request, err := http.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"dry_run":true}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	request.Header.Set("X-Kali-MCP-Async", "true")

	// When: the incompatible execution modes reach request preparation.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	defer response.Body.Close()

	// Then: validation fails before a process or job is created.
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}

func TestRunPostToolReturnsPendingJob(t *testing.T) {
	// Given: a regular POST tool route with the same job middleware used by streaming tools.
	jobStore := jobs.New(t.Context())
	artifacts, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() {
		jobStore.Close()
		if err := artifacts.Close(); err != nil {
			t.Errorf("close artifact store: %v", err)
		}
	})
	app := fiber.New()
	app.Use(httpapi.CallTelemetryMiddleware(nil))
	app.Use(httpapi.JobStoreMiddleware(jobStore))
	app.Use(httpapi.TargetSchedulerMiddleware(admission.NewScheduler(3, 3)))
	app.Use(httpapi.ArtifactStoreMiddleware(artifacts))
	app.Post("/tool", httpapi.WithExecutionLimit(httpapi.NewExecutionLimiter(1), func(c fiber.Ctx) error {
		return runTool(c, func(asyncExecutionRequest) error { return nil }, func(asyncExecutionRequest) ([]string, error) {
			return []string{"printf", "ok"}, nil
		})
	}))
	request, err := http.NewRequest(http.MethodPost, "/tool", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	request.Header.Set(dto.AsyncRequestHeader, "true")

	// When: the generic async transport marker reaches a non-streaming executable route.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("start async POST tool: %v", err)
	}
	defer response.Body.Close()
	var job dto.JobResponse
	if err := json.NewDecoder(response.Body).Decode(&job); err != nil {
		t.Fatalf("decode async response: %v", err)
	}

	// Then: the POST route starts the same pending job lifecycle instead of rejecting async execution.
	if response.StatusCode != http.StatusAccepted || job.Status != dto.JobPending || job.JobID == "" {
		t.Fatalf("unexpected async response: http=%d body=%+v", response.StatusCode, job)
	}
}

func TestCommandStreamReturnsPendingJob(t *testing.T) {
	// Given: the arbitrary command stream route with an asynchronous job store.
	jobStore := jobs.New(t.Context())
	artifacts, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() {
		jobStore.Close()
		if err := artifacts.Close(); err != nil {
			t.Errorf("close artifact store: %v", err)
		}
	})
	app := fiber.New()
	app.Use(httpapi.CallTelemetryMiddleware(nil))
	app.Use(httpapi.JobStoreMiddleware(jobStore))
	app.Use(httpapi.ArtifactStoreMiddleware(artifacts))
	app.Post("/command", httpapi.WithExecutionLimit(httpapi.NewExecutionLimiter(1), handleCommandStream))
	request, err := http.NewRequest(http.MethodPost, "/command", strings.NewReader(`{"command":"printf ok"}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	request.Header.Set(dto.AsyncRequestHeader, "true")

	// When: execute_command is selected through the generic async path.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("start async command: %v", err)
	}
	defer response.Body.Close()
	var job dto.JobResponse
	if err := json.NewDecoder(response.Body).Decode(&job); err != nil {
		t.Fatalf("decode async response: %v", err)
	}

	// Then: command execution returns immediately with a pending job handle.
	if response.StatusCode != http.StatusAccepted || job.Status != dto.JobPending || job.JobID == "" {
		t.Fatalf("unexpected async response: http=%d body=%+v", response.StatusCode, job)
	}
}
