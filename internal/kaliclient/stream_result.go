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
	stdoutBytes := a.stdoutBytes
	if stdoutBytes == 0 {
		stdoutBytes = streamLinesBytes(a.stdout)
	}
	stderrBytes := a.stderrBytes
	if stderrBytes == 0 {
		stderrBytes = streamLinesBytes(a.stderr)
	}
	stderrTruncated := a.stderrTruncated
	stderr := append([]string(nil), a.stderr...)
	if a.finalError != "" {
		retainStreamLine(&stderr, &stderrBytes, &stderrTruncated, a.finalError, a.retentionLimit())
	}
	return &dto.ToolResult{
		CallID: a.callID, Stdout: joinStreamLines(a.stdout), Stderr: joinStreamLines(stderr),
		StdoutBytes: stdoutBytes, StderrBytes: stderrBytes,
		OutputTruncated: a.stdoutTruncated || stderrTruncated,
		StdoutTruncated: a.stdoutTruncated, StderrTruncated: stderrTruncated,
		ReturnCode: a.returnCode, TimedOut: a.timedOut, Cancelled: a.cancelled,
		PartialResults: (a.timedOut || a.cancelled) && (len(a.stdout) > 0 || len(a.stderr) > 0),
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

func streamLinesBytes(lines []string) int {
	size := len(lines)
	for _, line := range lines {
		size += len(line)
	}
	return size
}

func joinStreamLines(lines []string) string {
	switch len(lines) {
	case 0:
		return ""
	case 1:
		return lines[0] + "\n"
	}
	size := len(lines)
	for _, line := range lines {
		size += len(line)
	}
	var joined strings.Builder
	joined.Grow(size)
	for _, line := range lines {
		joined.WriteString(line)
		joined.WriteByte('\n')
	}
	return joined.String()
}
