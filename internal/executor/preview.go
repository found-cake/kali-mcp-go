package executor

import (
	"context"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func PreviewExec(ctx context.Context, timeout time.Duration, name string, args ...string) *Result {
	if timeout <= 0 {
		timeout = dto.DefaultTimeout
	}
	startedAt := time.Now().UTC()
	tool := commandTool(name, args)
	result := &Result{
		Stdout: "dry run validated; tool was not executed", ReturnCode: 0,
		DryRun:    true,
		StartedAt: startedAt, Tool: tool, ToolVersion: toolVersion(ctx, tool),
		ArgvRedacted: redactArgs(name, args), Timeout: timeout,
		Warnings: []string{"dry_run enabled; no target request was sent"},
		Progress: &dto.ProgressMetadata{Phase: dto.ProgressCompleted, ResumeSupported: false},
	}
	result.Duration = time.Since(startedAt)
	return result
}
