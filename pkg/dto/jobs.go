package dto

import (
	"encoding/json"
	"time"
)

const AsyncRequestHeader = "X-Kali-MCP-Async"

type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobCompleted JobStatus = "completed"
	JobError     JobStatus = "error"
)

type JobRequest struct {
	JobID string `json:"job_id" jsonschema:"required,opaque job identifier returned by an asynchronous tool run"`
}

type AsyncToolRequest struct {
	ToolName  string          `json:"tool_name" jsonschema:"required,registered executable MCP tool name"`
	Arguments json.RawMessage `json:"arguments" jsonschema:"required,exact input object accepted by the selected dedicated tool"`
}

type JobPendingData struct {
	CallID                string            `json:"call_id"`
	Tool                  string            `json:"tool"`
	StartedAt             time.Time         `json:"started_at"`
	TimeoutMS             int64             `json:"timeout_ms"`
	Progress              *ProgressMetadata `json:"progress,omitempty"`
	CancellationRequested bool              `json:"cancellation_requested"`
}

type JobResponse struct {
	JobID     string          `json:"job_id"`
	Status    JobStatus       `json:"status" jsonschema:"pending|completed|error"`
	Data      json.RawMessage `json:"data"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
}

type JobLookupFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
