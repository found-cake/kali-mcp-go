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

func TestStartAsyncAddsInternalHeaderAndPreservesArguments(t *testing.T) {
	// Given: an executable endpoint that accepts internally marked asynchronous work.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/tools/nuclei/stream" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		if request.Header.Get(dto.AsyncRequestHeader) != "true" {
			t.Fatalf("missing asynchronous request header")
		}
		var arguments map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&arguments); err != nil {
			t.Fatalf("decode arguments: %v", err)
		}
		if _, found := arguments["async"]; found || string(arguments["target"]) != `"https://example.test"` {
			t.Fatalf("unexpected forwarded arguments: %s", arguments)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		fmt.Fprint(writer, `{"job_id":"job_test","status":"pending","data":{"call_id":"call_test","tool":"nuclei","started_at":"2026-09-06T00:00:00Z","timeout_ms":430000,"cancellation_requested":false}}`)
	}))
	defer server.Close()

	// When: the MCP-side client starts the selected endpoint through the generic async path.
	response, err := New(server.URL, time.Second, "token").StartAsync(
		context.Background(), "/api/tools/nuclei/stream", json.RawMessage(`{"target":"https://example.test"}`),
	)

	// Then: the pending job envelope is decoded without changing the dedicated tool arguments.
	if err != nil {
		t.Fatalf("start async tool: %v", err)
	}
	if response.Status != dto.JobPending || response.JobID != "job_test" {
		t.Fatalf("unexpected async response: %+v", response)
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
