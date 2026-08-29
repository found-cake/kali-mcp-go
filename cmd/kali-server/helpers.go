package main

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func toolStatus(lookup func(string) bool) map[string]bool {
	status := make(map[string]bool, len(exposedToolBinaries))
	dirWordlistReady := tools.WordlistExists(tools.DefaultDirWordlistPath())
	johnWordlistReady := tools.WordlistExists(tools.DefaultJohnWordlistPath())

	for _, toolName := range exposedToolBinaries {
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
	for _, toolName := range essentialToolBinaries {
		if !status[toolName] {
			return false
		}
	}
	return true
}

func toAPIResult(r *executor.Result) dto.ToolResult {
	result := dto.ToolResult{
		Stdout:          r.Stdout,
		Stderr:          r.Stderr,
		ReturnCode:      r.ReturnCode,
		TimedOut:        r.TimedOut,
		Cancelled:       r.Cancelled,
		PartialResults:  r.TimedOut && (r.Stdout != "" || r.Stderr != ""),
		ExecutionStatus: executionStatus(r),
		FindingStatus:   dto.FindingsUnknown,
		HTTPRequests:    r.HTTPRequests,
		DurationMS:      r.Duration.Milliseconds(),
		Execution: dto.ExecutionMetadata{
			Tool:            r.Tool,
			ToolVersion:     r.ToolVersion,
			ArgvRedacted:    r.ArgvRedacted,
			StartedAt:       r.StartedAt,
			TimeoutMS:       r.Timeout.Milliseconds(),
			Profile:         r.Policy.Profile,
			MaxRequests:     r.Policy.MaxRequests,
			RateLimit:       r.Policy.RateLimit,
			Concurrency:     r.Policy.Concurrency,
			HealthURL:       r.Policy.HealthURL,
			Max5xxResponses: r.Policy.Max5xxResponses,
		},
		Target:   r.Target,
		Warnings: r.Warnings,
	}
	if result.ExecutionStatus != dto.ExecutionSucceeded {
		result.Failure = &dto.FailureInfo{
			Code:      r.FailureCode,
			Message:   strings.TrimSpace(r.Stderr),
			Retryable: r.TimedOut || r.Cancelled,
		}
	}
	result.Finalize()
	return result
}

func executionStatus(r *executor.Result) dto.ExecutionStatus {
	if r.TimedOut {
		return dto.ExecutionTimedOut
	}
	if r.Cancelled {
		return dto.ExecutionCancelled
	}
	if r.ReturnCode != 0 {
		return dto.ExecutionFailed
	}
	return dto.ExecutionSucceeded
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
	if err := validate(req); err != nil {
		return req, err
	}
	return req, nil
}
