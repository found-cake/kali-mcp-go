package kaliclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type streamAccumulator struct {
	stdout            []string
	stderr            []string
	returnCode        int
	timedOut          bool
	cancelled         bool
	done              bool
	finalError        string
	httpRequests      *int
	durationMS        int64
	failure           *dto.FailureInfo
	execution         dto.ExecutionMetadata
	target            *dto.TargetProvenance
	spaBaseline       *dto.SPABaseline
	falsePositiveRisk string
	warnings          []string
	artifacts         []dto.ArtifactRef
	callID            string
	progress          *dto.ProgressMetadata
}

func (c *Client) Stream(ctx context.Context, endpoint string, body any) (*dto.ToolResult, error) {
	requestContext, cancel := c.requestContext(ctx, body)
	defer cancel()
	request, err := c.newJSONRequest(requestContext, jsonRequestSpec{
		method: http.MethodPost, endpoint: endpoint, body: body, authorize: true,
	})
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		responseBody, _ := io.ReadAll(response.Body)
		return nil, serverResponseError(response, responseBody)
	}
	return parseToolStream(response.Body, response.Header.Get(dto.CallIDHeader))
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
			return nil, fmt.Errorf("stream decode event: %w", err)
		}
		if err := accumulator.consume(event); err != nil {
			return nil, err
		}
		if accumulator.done {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("stream read: %w", err)
	}
	return accumulator.result()
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
		a.durationMS = event.DurationMS
		a.failure = event.Failure
		a.execution = event.Execution
		a.target = event.Target
		a.spaBaseline = event.SPABaseline
		a.falsePositiveRisk = event.FalsePositiveRisk
		a.warnings = append(a.warnings, event.Warnings...)
		a.artifacts = append(a.artifacts, event.Artifacts...)
		a.progress = event.Progress
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

func (a *streamAccumulator) result() (*dto.ToolResult, error) {
	if !a.done {
		return nil, fmt.Errorf("stream ended without done event")
	}
	if a.finalError != "" {
		a.stderr = append(a.stderr, a.finalError)
	}
	result := &dto.ToolResult{
		CallID: a.callID, Stdout: joinStreamLines(a.stdout), Stderr: joinStreamLines(a.stderr),
		ReturnCode: a.returnCode, TimedOut: a.timedOut, Cancelled: a.cancelled,
		PartialResults: (a.timedOut || a.cancelled) && (len(a.stdout) > 0 || len(a.stderr) > 0),
		HTTPRequests:   a.httpRequests, DurationMS: a.durationMS, Failure: a.failure, Execution: a.execution,
		Target: a.target, SPABaseline: a.spaBaseline, FalsePositiveRisk: a.falsePositiveRisk,
		Warnings: a.warnings, Artifacts: a.artifacts, Progress: a.progress, FindingStatus: dto.FindingsUnknown,
		ExecutionStatus: dto.ExecutionStatusFromResult(a.returnCode, a.timedOut, a.cancelled),
	}
	result.Finalize()
	return result, nil
}

func joinStreamLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
