package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func toolStatus(lookup func(string) bool) map[string]bool {
	runtimeTools := tools.RuntimeToolNames()
	status := make(map[string]bool, len(runtimeTools))
	dirWordlistReady := tools.WordlistExists(tools.DefaultDirWordlistPath())
	johnWordlistReady := tools.WordlistExists(tools.DefaultJohnWordlistPath())

	for _, toolName := range runtimeTools {
		ready := lookup(toolName)
		switch toolName {
		case "gobuster", "dirb":
			ready = ready && dirWordlistReady
		case "john":
			ready = ready && johnWordlistReady
		}
		status[toolName] = ready
	}

	return status
}

func allEssentialToolsAvailable(status map[string]bool) bool {
	for _, toolName := range tools.EssentialRuntimeToolNames() {
		if !status[toolName] {
			return false
		}
	}
	return true
}

func toAPIResult(r *executor.Result) dto.ToolResult {
	result := dto.ToolResult{
		CallID:             r.CallID,
		Stdout:             r.Stdout,
		Stderr:             r.Stderr,
		StdoutBytes:        len(r.Stdout),
		StderrBytes:        len(r.Stderr),
		ReturnCode:         r.ReturnCode,
		TimedOut:           r.TimedOut,
		Cancelled:          r.Cancelled,
		PartialResults:     r.TimedOut && (r.Stdout != "" || r.Stderr != ""),
		ExecutionStatus:    dto.ExecutionStatusFromResult(r.ReturnCode, r.TimedOut, r.Cancelled),
		FindingStatus:      dto.FindingsUnknown,
		HTTPRequests:       r.HTTPRequests,
		RequestCountSource: r.RequestCountSource,
		DurationMS:         r.Duration.Milliseconds(),
		Execution: dto.ExecutionMetadata{
			Tool:            r.Tool,
			ToolVersion:     r.ToolVersion,
			ArgvRedacted:    r.ArgvRedacted,
			StartedAt:       r.StartedAt,
			EndedAt:         r.StartedAt.Add(r.Duration),
			TimeoutMS:       r.Timeout.Milliseconds(),
			TimeoutPlanning: r.TimeoutPlanning,
			ProcessStarted:  r.ProcessStarted,
			GracefulStopMS:  r.GracefulStop.Milliseconds(),
			DryRun:          r.DryRun,
			Profile:         r.Policy.Profile,
			MaxRequests:     r.Policy.MaxRequests,
			RateLimit:       r.Policy.RateLimit,
			Concurrency:     r.Policy.Concurrency,
			HealthURL:       r.Policy.HealthURL,
			Max5xxResponses: r.Policy.Max5xxResponses,
			Controls:        r.Controls,
		},
		Target:            r.Target,
		SPABaseline:       r.SPABaseline,
		FalsePositiveRisk: r.FalsePositiveRisk,
		Warnings:          r.Warnings,
		Artifacts:         r.Artifacts,
		HTTPRequest:       r.HTTPRequest,
		HTTPResponse:      r.HTTPResponse,
		Progress:          r.Progress,
		JWTAnalysis:       r.JWTAnalysis,
		SQLMapAnalysis:    r.SQLMapAnalysis,
		Evidence:          r.Evidence,
	}
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		result.Failure = &dto.FailureInfo{
			Code:          r.FailureCode,
			Message:       strings.TrimSpace(r.Stderr),
			Retryable:     r.TimedOut || r.Cancelled,
			RetryEstimate: &dto.RetryEstimate{MaximumRequests: r.Policy.MaxRequests, TimeoutMS: r.Timeout.Milliseconds()},
		}
	}
	result.Finalize()
	return result
}

func badRequest(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
}

func internalServerError(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": msg})
}

func serviceUnavailable(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": msg})
}

func bindJSON(c fiber.Ctx, dst any) error {
	return c.Bind().Body(dst)
}

func parseRequest[T any](c fiber.Ctx, validate func(T) error) (T, error) {
	var req T
	bindErr := bindJSON(c, &req)
	if bindErr != nil {
		return req, fmt.Errorf("invalid request body")
	}
	if err := tools.ValidateRequestSecrets(req); err != nil {
		return req, err
	}
	resolved, err := targeting.ApplyContext(apiTokenFromContext(c), req, time.Now().UTC())
	if err != nil {
		return req, err
	}
	req = resolved
	if err := validate(req); err != nil {
		return req, err
	}
	return req, nil
}
