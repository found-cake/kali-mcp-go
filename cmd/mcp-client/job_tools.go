package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	toolmeta "github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type streamToolOutput struct {
	encoded json.RawMessage
}

func (output streamToolOutput) MarshalJSON() ([]byte, error) {
	return output.encoded, nil
}

func newStreamToolOutput(result dto.ToolResult) (streamToolOutput, error) {
	return encodeStreamToolOutput(result)
}

func newAsyncStreamToolOutput(result dto.JobResponse) (streamToolOutput, error) {
	return encodeStreamToolOutput(result)
}

func encodeStreamToolOutput[T dto.ToolResult | dto.JobResponse](value T) (streamToolOutput, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return streamToolOutput{}, fmt.Errorf("encode stream tool output: %w", err)
	}
	return streamToolOutput{encoded: encoded}, nil
}

type jobOperation func(context.Context, dto.JobRequest) (*dto.JobResponse, error)

type jobToolRegistration struct {
	name        string
	description string
	operation   jobOperation
}

func registerScanJobs(server *mcp.Server, kali *kaliclient.Client) {
	registrations := []jobToolRegistration{
		{name: "scan_job_status", description: "Inspect pending progress or terminal status for an asynchronous scan job.", operation: kali.JobStatus},
		{name: "scan_job_result", description: "Read the existing ToolResult from an asynchronous scan job; terminal results remain available for 30 seconds after process exit.", operation: kali.JobResult},
		{name: "scan_job_cancel", description: "Request cancellation of a running asynchronous scan job.", operation: kali.JobCancel},
	}
	for _, registration := range registrations {
		tool := &mcp.Tool{
			Name: registration.name, Description: registration.description,
			OutputSchema: jobResponseOutputSchema(),
		}
		mcp.AddTool(server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.JobRequest) (*mcp.CallToolResult, dto.JobResponse, error) {
			response, err := registration.operation(ctx, request)
			return jobMCPResult(response, err)
		})
	}
}

func jobMCPResult(response *dto.JobResponse, operationErr error) (*mcp.CallToolResult, dto.JobResponse, error) {
	if operationErr != nil {
		return nil, dto.JobResponse{}, operationErr
	}
	normalized, result, err := normalizeJobResponse(*response)
	if err != nil {
		return nil, dto.JobResponse{}, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, dto.JobResponse{}, fmt.Errorf("encode job response text: %w", err)
	}
	text := string(encoded)
	if result != nil {
		text = result.Format()
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: normalized.Status == dto.JobError,
	}, normalized, nil
}

func normalizeJobResponse(response dto.JobResponse) (dto.JobResponse, *dto.ToolResult, error) {
	if response.Status == dto.JobPending {
		return response, nil, nil
	}
	var identity struct {
		CallID          string              `json:"call_id"`
		ExecutionStatus dto.ExecutionStatus `json:"execution_status"`
		Execution       struct {
			Tool string `json:"tool"`
		} `json:"execution"`
	}
	if err := json.Unmarshal(response.Data, &identity); err != nil {
		return dto.JobResponse{}, nil, fmt.Errorf("decode job data identity: %w", err)
	}
	if identity.CallID == "" || identity.ExecutionStatus == "" {
		return response, nil, nil
	}
	var result dto.ToolResult
	if err := json.Unmarshal(response.Data, &result); err != nil {
		return dto.JobResponse{}, nil, fmt.Errorf("decode job tool result: %w", err)
	}
	toolName, found := toolmeta.AsyncMCPToolForRuntime(identity.Execution.Tool)
	if found {
		result = classifyToolResult(toolName, result)
		result = compactToolResult(toolName, result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return dto.JobResponse{}, nil, fmt.Errorf("encode normalized job result: %w", err)
	}
	response.Data = encoded
	response.Status = dto.JobError
	if result.ExecutionStatus == dto.ExecutionSucceeded {
		response.Status = dto.JobCompleted
	}
	return response, &result, nil
}
