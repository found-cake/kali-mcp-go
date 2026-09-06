package kaliclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/callid"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type streamAccumulator struct {
	stdout             []string
	stderr             []string
	returnCode         int
	timedOut           bool
	cancelled          bool
	done               bool
	finalError         string
	httpRequests       *int
	requestCountSource dto.RequestCountSource
	durationMS         int64
	failure            *dto.FailureInfo
	execution          dto.ExecutionMetadata
	target             *dto.TargetProvenance
	spaBaseline        *dto.SPABaseline
	falsePositiveRisk  string
	warnings           []string
	artifacts          []dto.ArtifactRef
	callID             string
	progress           *dto.ProgressMetadata
	jwtAnalysis        *dto.JWTAnalysisMetadata
	sqlmapAnalysis     *dto.SQLMapAnalysis
	nucleiPreview      *dto.NucleiPreviewMetadata
	evidence           *dto.EvidenceManifest
}

type StreamInvocation struct {
	Result *dto.ToolResult
	Job    *dto.JobResponse
}

func (c *Client) Stream(ctx context.Context, endpoint string, body any) (*dto.ToolResult, error) {
	invocation, err := c.InvokeStream(ctx, endpoint, body)
	if err != nil {
		return invocation.Result, err
	}
	if invocation.Job != nil {
		return nil, fmt.Errorf("stream request started asynchronous job %s", invocation.Job.JobID)
	}
	return invocation.Result, nil
}

func (c *Client) InvokeStream(ctx context.Context, endpoint string, body any) (StreamInvocation, error) {
	callID, err := callid.New()
	if err != nil {
		return StreamInvocation{}, fmt.Errorf("stream call ID: %w", err)
	}
	requestContext, cancel := c.requestContext(ctx, body)
	defer cancel()
	request, err := c.newJSONRequest(requestContext, jsonRequestSpec{
		method: http.MethodPost, endpoint: endpoint, body: body, authorize: true,
	})
	if err != nil {
		return StreamInvocation{Result: &dto.ToolResult{CallID: callID}}, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set(dto.CallIDHeader, callID)
	response, err := c.http.Do(request)
	if err != nil {
		c.cancelRemoteCall(callID)
		if contextError := requestContext.Err(); contextError != nil {
			err = contextError
		}
		return StreamInvocation{Result: &dto.ToolResult{CallID: callID}}, fmt.Errorf("stream: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		responseBody, _ := io.ReadAll(response.Body)
		return StreamInvocation{}, serverResponseError(response, responseBody)
	}
	if response.StatusCode == http.StatusAccepted || strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		var job dto.JobResponse
		if err := json.NewDecoder(response.Body).Decode(&job); err != nil {
			return StreamInvocation{}, fmt.Errorf("decode asynchronous job: %w", err)
		}
		return StreamInvocation{Job: &job}, nil
	}
	responseCallID := response.Header.Get(dto.CallIDHeader)
	if responseCallID == "" {
		responseCallID = callID
	}
	result, err := parseToolStream(response.Body, responseCallID)
	if err != nil {
		c.cancelRemoteCall(callID)
		if contextError := requestContext.Err(); contextError != nil {
			err = fmt.Errorf("stream: %w", contextError)
		}
	}
	return StreamInvocation{Result: result}, err
}

func (c *Client) cancelRemoteCall(callID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := c.newJSONRequest(ctx, jsonRequestSpec{
		method: http.MethodPost, endpoint: "/api/calls/" + callID + "/cancel", authorize: true,
	})
	if err != nil {
		return
	}
	response, err := c.http.Do(request)
	if err == nil {
		response.Body.Close()
	}
}

func parseToolStream(reader io.Reader, initialCallID string) (*dto.ToolResult, error) {
	accumulator := streamAccumulator{callID: initialCallID}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		if !strings.HasPrefix(raw, "data: ") {
			continue
		}
		var event dto.StreamEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(raw, "data: ")), &event); err != nil {
			return accumulator.partialResult(), fmt.Errorf("stream decode event: %w", err)
		}
		if err := accumulator.consume(event); err != nil {
			return accumulator.partialResult(), err
		}
		if accumulator.done {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return accumulator.partialResult(), fmt.Errorf("stream read: %w", err)
	}
	result, err := accumulator.result()
	if err != nil {
		return accumulator.partialResult(), err
	}
	return result, nil
}

func (a *streamAccumulator) consume(event dto.StreamEvent) error {
	if event.Error != "" && !event.Done {
		return fmt.Errorf("server: %s", event.Error)
	}
	if event.Progress != nil {
		a.progress = event.Progress
	}
	if event.Heartbeat {
		return nil
	}
	if event.Done {
		if event.ReturnCode == nil {
			return fmt.Errorf("stream done event missing return_code")
		}
		a.returnCode = *event.ReturnCode
		if event.CallID != "" {
			a.callID = event.CallID
		}
		a.timedOut = event.TimedOut
		a.cancelled = event.Cancelled
		a.finalError = event.Error
		a.httpRequests = event.HTTPRequests
		a.requestCountSource = event.RequestCountSource
		a.durationMS = event.DurationMS
		a.failure = event.Failure
		a.execution = event.Execution
		a.target = event.Target
		a.spaBaseline = event.SPABaseline
		a.falsePositiveRisk = event.FalsePositiveRisk
		a.warnings = append(a.warnings, event.Warnings...)
		a.artifacts = append(a.artifacts, event.Artifacts...)
		a.progress = event.Progress
		a.jwtAnalysis = event.JWTAnalysis
		a.sqlmapAnalysis = event.SQLMapAnalysis
		a.nucleiPreview = event.NucleiPreview
		a.evidence = event.Evidence
		a.done = true
		return nil
	}
	switch event.Stream {
	case "stdout":
		a.stdout = append(a.stdout, event.Line)
	case "stderr":
		a.stderr = append(a.stderr, event.Line)
	}
	return nil
}
