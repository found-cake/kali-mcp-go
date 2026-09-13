package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/jobs"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestJobHandlersExposePendingStateAndCancellation(t *testing.T) {
	// Given: a running server-owned job and authenticated job routes.
	store := jobs.New(t.Context())
	started := make(chan struct{})
	created, err := store.Start(jobs.StartSpec{
		CallID: "call_http", Tool: "nuclei_scan", Timeout: time.Minute,
		Run: func(ctx context.Context, _ jobs.ProgressReporter) dto.ToolResult {
			close(started)
			<-ctx.Done()
			return dto.ToolResult{CallID: "call_http", ExecutionStatus: dto.ExecutionCancelled, Cancelled: true, ReturnCode: -1}
		},
	})
	if err != nil {
		t.Fatalf("start job: %v", err)
	}
	defer store.Close()
	<-started
	app := fiber.New()
	app.Use(JobStoreMiddleware(store))
	app.Get("/jobs/:id/status", HandleJobStatus)
	app.Post("/jobs/:id/cancel", HandleJobCancel)

	// When: a caller checks status and requests cancellation.
	statusResponse, err := app.Test(newJobRequest(t, http.MethodGet, "/jobs/"+created.ID+"/status"))
	if err != nil {
		t.Fatalf("get job status: %v", err)
	}
	defer statusResponse.Body.Close()
	var status dto.JobResponse
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatalf("decode job status: %v", err)
	}
	cancelResponse, err := app.Test(newJobRequest(t, http.MethodPost, "/jobs/"+created.ID+"/cancel"))
	if err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	defer cancelResponse.Body.Close()
	var cancelling dto.JobResponse
	if err := json.NewDecoder(cancelResponse.Body).Decode(&cancelling); err != nil {
		t.Fatalf("decode cancellation: %v", err)
	}

	// Then: both responses use the pending/data envelope and cancellation intent is explicit.
	if statusResponse.StatusCode != http.StatusOK || status.Status != dto.JobPending {
		t.Fatalf("unexpected status response: http=%d body=%+v", statusResponse.StatusCode, status)
	}
	var pending dto.JobPendingData
	if err := json.Unmarshal(cancelling.Data, &pending); err != nil {
		t.Fatalf("decode pending data: %v", err)
	}
	if cancelling.Status != dto.JobPending || !pending.CancellationRequested || pending.CallID != "call_http" {
		t.Fatalf("unexpected cancellation response: response=%+v data=%+v", cancelling, pending)
	}
}

func TestJobHandlersReturnStructuredExpiredError(t *testing.T) {
	// Given: job routes with no matching retained job.
	store := jobs.New(t.Context())
	defer store.Close()
	app := fiber.New()
	app.Use(JobStoreMiddleware(store))
	app.Get("/jobs/:id/result", HandleJobResult)

	// When: a caller asks for an unknown or expired job.
	response, err := app.Test(newJobRequest(t, http.MethodGet, "/jobs/job_missing/result"))
	if err != nil {
		t.Fatalf("get missing job: %v", err)
	}
	defer response.Body.Close()
	var result dto.JobResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode missing job: %v", err)
	}

	// Then: HTTP 404 still carries the async status/data contract.
	if response.StatusCode != http.StatusNotFound || result.Status != dto.JobError {
		t.Fatalf("unexpected missing response: http=%d body=%+v", response.StatusCode, result)
	}
	var failure dto.JobLookupFailure
	if err := json.Unmarshal(result.Data, &failure); err != nil {
		t.Fatalf("decode missing data: %v", err)
	}
	if failure.Code != "job_not_found_or_expired" {
		t.Fatalf("unexpected failure data: %+v", failure)
	}
}

func newJobRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("create job request: %v", err)
	}
	return request
}
