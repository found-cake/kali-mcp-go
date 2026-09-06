package kaliclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestInvokeStreamDecodesAcceptedAsyncJob(t *testing.T) {
	// Given: a stream endpoint that accepted work into the server job store.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/tools/nuclei/stream" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		fmt.Fprint(writer, `{"job_id":"job_test","status":"pending","data":{"call_id":"call_test","tool":"nuclei","started_at":"2026-09-06T00:00:00Z","timeout_ms":430000,"cancellation_requested":false}}`)
	}))
	defer server.Close()

	// When: the MCP-side client invokes the stream endpoint in async mode.
	invocation, err := New(server.URL, time.Second, "token").InvokeStream(
		context.Background(), "/api/tools/nuclei/stream", dto.NucleiRequest{ScanOptions: dto.ScanOptions{Async: true}},
	)

	// Then: the accepted envelope is returned without attempting SSE parsing.
	if err != nil {
		t.Fatalf("invoke async stream: %v", err)
	}
	if invocation.Job == nil || invocation.Result != nil || invocation.Job.Status != dto.JobPending || invocation.Job.JobID != "job_test" {
		t.Fatalf("unexpected async invocation: %+v", invocation)
	}
}

func TestJobOperationsPreserveStatusDataOnNotFound(t *testing.T) {
	// Given: job endpoints that return a structured expired envelope with HTTP 404.
	requests := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.Method + " " + request.URL.Path
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNotFound)
		fmt.Fprint(writer, `{"job_id":"job_missing","status":"error","data":{"code":"job_not_found_or_expired","message":"expired"}}`)
	}))
	defer server.Close()
	client := New(server.URL, time.Second, "token")

	// When: status, result, and cancellation operations target the expired job.
	status, statusErr := client.JobStatus(context.Background(), dto.JobRequest{JobID: "job_missing"})
	result, resultErr := client.JobResult(context.Background(), dto.JobRequest{JobID: "job_missing"})
	cancelled, cancelErr := client.JobCancel(context.Background(), dto.JobRequest{JobID: "job_missing"})

	// Then: HTTP status does not discard the application-level error envelope or route contract.
	if statusErr != nil || resultErr != nil || cancelErr != nil {
		t.Fatalf("job operations returned transport errors: status=%v result=%v cancel=%v", statusErr, resultErr, cancelErr)
	}
	for _, response := range []*dto.JobResponse{status, result, cancelled} {
		if response.Status != dto.JobError {
			t.Fatalf("unexpected job response: %+v", response)
		}
		var failure dto.JobLookupFailure
		if err := json.Unmarshal(response.Data, &failure); err != nil || failure.Code != "job_not_found_or_expired" {
			t.Fatalf("unexpected job data: decode=%v data=%+v", err, failure)
		}
	}
	want := []string{
		"GET /api/jobs/job_missing/status",
		"GET /api/jobs/job_missing/result",
		"POST /api/jobs/job_missing/cancel",
	}
	for _, expected := range want {
		if got := <-requests; got != expected {
			t.Fatalf("job route=%q want=%q", got, expected)
		}
	}
}
