package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/found-cake/kali-mcp-go/internal/kaliclient"
	toolmeta "github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type jobOperation func(context.Context, dto.JobRequest) (*dto.JobResponse, error)

type jobToolRegistration struct {
	name        string
	description string
	operation   jobOperation
}

func registerAsyncJobs(server *mcp.Server, kali *kaliclient.Client, schemas toolInputSchemaCatalog) error {
	if err := registerAsyncTool(server, kali, schemas); err != nil {
		return err
	}
	registrations := []jobToolRegistration{
		{name: "scan_job_status", description: "Inspect pending progress or terminal status for an asynchronous tool job.", operation: kali.JobStatus},
		{name: "scan_job_result", description: "Read the existing ToolResult from an asynchronous tool job; terminal results remain available for 30 seconds after process exit.", operation: kali.JobResult},
		{name: "scan_job_cancel", description: "Request cancellation of a running asynchronous tool job.", operation: kali.JobCancel},
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
	return nil
}

func registerAsyncTool(server *mcp.Server, kali *kaliclient.Client, schemas toolInputSchemaCatalog) error {
	validators, err := resolveAsyncToolSchemas(schemas)
	if err != nil {
		return err
	}
	tool := &mcp.Tool{
		Name:        "run_tool_async",
		Description: "Start any registered executable tool as a new asynchronous run. Async avoids the MCP host deadline but preserves arguments.timeout. For a broad low-rate scan, set that timeout high enough to finish. After a process timeout, start a new run with a longer timeout or narrower scope; this is not resume.",
		InputSchema: asyncToolInputSchema(), OutputSchema: jobResponseOutputSchema(),
	}
	mcp.AddTool(server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, request dto.AsyncToolRequest) (*mcp.CallToolResult, dto.JobResponse, error) {
		definition, found := toolmeta.ToolCapability(request.ToolName)
		if !found {
			return nil, dto.JobResponse{}, fmt.Errorf("unknown executable tool %q", request.ToolName)
		}
		if err := validateAsyncArguments(validators[request.ToolName], request.Arguments); err != nil {
			return nil, dto.JobResponse{}, fmt.Errorf("invalid %s arguments: %w", request.ToolName, err)
		}
		response, err := kali.StartAsync(ctx, definition.Endpoint, request.Arguments)
		return jobMCPResult(response, err)
	})
	return nil
}

func resolveAsyncToolSchemas(schemas toolInputSchemaCatalog) (map[string]*jsonschema.Resolved, error) {
	resolved := make(map[string]*jsonschema.Resolved, len(schemas))
	for _, name := range toolmeta.ExecutableToolNames() {
		raw, found := schemas[name]
		if !found {
			return nil, fmt.Errorf("missing registered input schema for %s", name)
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, fmt.Errorf("decode %s input schema: %w", name, err)
		}
		validator, err := schema.Resolve(nil)
		if err != nil {
			return nil, fmt.Errorf("resolve %s input schema: %w", name, err)
		}
		resolved[name] = validator
	}
	return resolved, nil
}

func validateAsyncArguments(validator *jsonschema.Resolved, raw json.RawMessage) error {
	var arguments map[string]any
	if err := json.Unmarshal(raw, &arguments); err != nil || arguments == nil {
		return fmt.Errorf("arguments must be a JSON object")
	}
	if err := validator.Validate(arguments); err != nil {
		return err
	}
	return nil
}

func asyncToolInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"tool_name": {Type: "string", Enum: stringEnums(toolmeta.ExecutableToolNames())},
			"arguments": objectSchema(),
		},
		Required: []string{"tool_name", "arguments"},
	}
}

func stringEnums(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
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
	toolName, found := toolmeta.MCPToolForRuntime(identity.Execution.Tool)
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
