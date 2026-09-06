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
	request, err := http.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"async":true}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

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
	request, err := http.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"async":true,"dry_run":true}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

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
