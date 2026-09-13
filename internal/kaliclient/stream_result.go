package kaliclient

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (a *streamAccumulator) result() (*dto.ToolResult, error) {
	if !a.done {
		return nil, fmt.Errorf("stream ended without done event")
	}
	result := a.baseResult()
	result.ExecutionStatus = dto.ExecutionStatusFromResult(a.returnCode, a.timedOut, a.cancelled)
	if result.ExecutionStatus == dto.ExecutionSucceeded && result.Failure != nil {
		result.ExecutionStatus = dto.ExecutionFailed
	}
	result.Finalize()
	return result, nil
}

func (a *streamAccumulator) partialResult() *dto.ToolResult {
	result := a.baseResult()
	result.ReturnCode = -1
	result.ExecutionStatus = dto.ExecutionFailed
	result.PartialResults = result.Stdout != "" || result.Stderr != "" || result.HTTPRequests != nil || result.Progress != nil && result.Progress.ObservedOutputItems > 0
	result.Finalize()
	return result
}

func (a *streamAccumulator) baseResult() *dto.ToolResult {
	stdout := a.stdout.builder.String()
	stdoutBytes := a.stdout.observedBytes
	if stdoutBytes == 0 {
		stdoutBytes = len(stdout)
	}
	stderr := a.stderr.builder.String()
	stderrBytes := a.stderr.observedBytes
	if stderrBytes == 0 {
		stderrBytes = len(stderr)
	}
	stderrTruncated := a.stderr.truncated
	if a.finalError != "" {
		stderr, stderrBytes, stderrTruncated = appendFinalError(stderr, stderrBytes, stderrTruncated, a.finalError, a.retentionLimit())
	}
	return &dto.ToolResult{
		CallID: a.callID, Stdout: stdout, Stderr: stderr,
		StdoutBytes: stdoutBytes, StderrBytes: stderrBytes,
		OutputTruncated: a.stdout.truncated || stderrTruncated,
		StdoutTruncated: a.stdout.truncated, StderrTruncated: stderrTruncated,
		ReturnCode: a.returnCode, TimedOut: a.timedOut, Cancelled: a.cancelled,
		PartialResults: (a.timedOut || a.cancelled) && (a.stdout.builder.Len() > 0 || a.stderr.builder.Len() > 0),
		HTTPRequests:   a.httpRequests, RequestCountSource: a.requestCountSource,
		DurationMS: a.durationMS, Failure: a.failure, Execution: a.execution,
		Target: a.target, SPABaseline: a.spaBaseline, FalsePositiveRisk: a.falsePositiveRisk,
		Warnings: a.warnings, Artifacts: a.artifacts, Progress: a.progress, FindingStatus: dto.FindingsUnknown,
		JWTAnalysis:    a.jwtAnalysis,
		SQLMapAnalysis: a.sqlmapAnalysis,
		NucleiPreview:  a.nucleiPreview,
		Evidence:       a.evidence,
	}
}

func appendFinalError(stderr string, stderrBytes int, truncated bool, finalError string, limit int) (string, int, bool) {
	lineBytes := len(finalError) + 1
	stderrBytes += lineBytes
	if truncated || len(stderr)+lineBytes > limit {
		return stderr, stderrBytes, true
	}
	var output strings.Builder
	output.Grow(len(stderr) + lineBytes)
	output.WriteString(stderr)
	output.WriteString(finalError)
	output.WriteByte('\n')
	return output.String(), stderrBytes, false
}
