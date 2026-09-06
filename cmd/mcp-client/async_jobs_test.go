package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPAsyncScanStartsAndReturnsTerminalJobData(t *testing.T) {
	// Given: an HTTP execution server that accepts a Nuclei job and later returns its raw result.
	httpServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/tools/nuclei/stream":
			writer.WriteHeader(http.StatusAccepted)
			fmt.Fprint(writer, `{"job_id":"job_mcp","status":"pending","data":{"call_id":"call_mcp","tool":"nuclei","started_at":"2026-09-06T00:00:00Z","timeout_ms":60000,"cancellation_requested":false}}`)
		case "/api/jobs/job_mcp/result":
			fmt.Fprint(writer, `{"job_id":"job_mcp","status":"completed","data":{"call_id":"call_mcp","stdout":"","stderr":"","return_code":0,"execution_status":"succeeded","execution":{"tool":"nuclei"}}}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer httpServer.Close()
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	if err := registerTools(server, kaliclient.New(httpServer.URL, time.Second, "token")); err != nil {
		t.Fatalf("register tools: %v", err)
	}
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(t.Context(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect MCP server: %v", err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(t.Context(), clientTransport, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	defer clientSession.Close()

	// When: the scanner starts asynchronously and its terminal result is fetched.
	started, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "nuclei_scan", Arguments: dto.NucleiRequest{
			ScanOptions: dto.ScanOptions{Async: true}, Target: "http://example.test", Tags: "http", Timeout: 60,
		},
	})
	if err != nil {
		t.Fatalf("start async MCP scan: %v", err)
	}
	terminal, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan_job_result", Arguments: dto.JobRequest{JobID: "job_mcp"},
	})
	if err != nil {
		t.Fatalf("fetch async MCP result: %v", err)
	}

	// Then: both calls use status/data envelopes and terminal data is the existing classified ToolResult.
	var pending dto.JobResponse
	pendingJSON, err := json.Marshal(started.StructuredContent)
	if err != nil {
		t.Fatalf("encode pending MCP output: %v", err)
	}
	if err := json.Unmarshal(pendingJSON, &pending); err != nil {
		t.Fatalf("decode pending MCP output: %v", err)
	}
	var completed dto.JobResponse
	completedJSON, err := json.Marshal(terminal.StructuredContent)
	if err != nil {
		t.Fatalf("encode terminal MCP output: %v", err)
	}
	if err := json.Unmarshal(completedJSON, &completed); err != nil {
		t.Fatalf("decode terminal MCP output: %v", err)
	}
	var result dto.ToolResult
	if err := json.Unmarshal(completed.Data, &result); err != nil {
		t.Fatalf("decode terminal tool data: %v", err)
	}
	if pending.Status != dto.JobPending || completed.Status != dto.JobCompleted {
		t.Fatalf("unexpected job statuses: pending=%q completed=%q", pending.Status, completed.Status)
	}
	pendingText, ok := started.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(pendingText.Text, `"job_id":"job_mcp"`) {
		t.Fatalf("pending text omits job handle: %#v", started.Content)
	}
	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsNotDetected || result.CallID != "call_mcp" {
		t.Fatalf("unexpected terminal tool result: %+v", result)
	}
}
