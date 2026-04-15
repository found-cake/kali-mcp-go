package main

import (
	"context"
	"fmt"
	"os"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func runTool[T any](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	req, err := parseRequest(c, validate)
	if err != nil {
		return badRequest(c, err.Error())
	}
	args, err := argsFor(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	if len(args) == 0 {
		return internalServerError(c, "internal error: no command generated")
	}
	return c.JSON(toAPIResult(executor.RunExec(c.Context(), 0, args[0], args[1:]...)))
}

func runToolStream[T dto.TimeoutRequest](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
	req, err := parseRequest(c, validate)
	if err != nil {
		return badRequest(c, err.Error())
	}
	args, err := argsFor(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	if len(args) == 0 {
		return internalServerError(c, "internal error: no command generated")
	}
	execCtx, cancel := context.WithCancel(c.Context())
	timeout := commandTimeout(req.GetRequestTimeout())
	lines, done := executor.StreamExec(execCtx, timeout, args[0], args[1:]...)
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release)
}

func handleCommand(c fiber.Ctx) error {
	req, err := parseRequest(c, func(r dto.CommandRequest) error {
		if r.Command == "" {
			return fmt.Errorf("command is required")
		}
		return nil
	})
	if err != nil {
		return badRequest(c, err.Error())
	}
	timeout := commandTimeout(req.Timeout)
	result := executor.RunShell(c.Context(), timeout, req.Command)
	return c.JSON(toAPIResult(result))
}

func handleCommandStream(c fiber.Ctx) error {
	req, err := parseRequest(c, func(r dto.CommandRequest) error {
		if r.Command == "" {
			return fmt.Errorf("command is required")
		}
		return nil
	})
	if err != nil {
		return badRequest(c, err.Error())
	}
	timeout := commandTimeout(req.Timeout)
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamShell(execCtx, timeout, req.Command)
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release)
}

func handleNmapStream(c fiber.Ctx) error {
	return runToolStream(c, validateNmapRequest, tools.NmapArgs)
}

func handleGobuster(c fiber.Ctx) error {
	return runTool(c, func(req dto.GobusterRequest) error {
		if req.URL == "" {
			return fmt.Errorf("url is required")
		}
		if !tools.ValidGobusterMode(req.Mode) {
			return fmt.Errorf("mode must be dir|dns|fuzz|vhost")
		}
		return nil
	}, tools.GobusterArgs)
}

func handleDirbStream(c fiber.Ctx) error {
	return runToolStream(c, validateDirbRequest, tools.DirbArgs)
}

func handleNiktoStream(c fiber.Ctx) error {
	return runToolStream(c, validateNiktoRequest, tools.NiktoArgs)
}

func handleWPScanStream(c fiber.Ctx) error {
	return runToolStream(c, validateWPScanRequest, tools.WPScanArgs)
}

func handleEnum4linuxStream(c fiber.Ctx) error {
	return runToolStream(c, validateEnum4linuxRequest, tools.Enum4linuxArgs)
}

func handleSQLMapStream(c fiber.Ctx) error {
	return runToolStream(c, validateSQLMapRequest, tools.SQLMapArgs)
}

func handleTsharkStream(c fiber.Ctx) error {
	return runToolStream(c, validateTsharkRequest, tools.TsharkArgs)
}

func handleMetasploit(c fiber.Ctx) error {
	req, err := parseRequest(c, func(r dto.MetasploitRequest) error {
		if r.Module == "" {
			return fmt.Errorf("module is required")
		}
		if containsLineBreak(r.Module) {
			return fmt.Errorf("module must not contain line breaks")
		}
		for k, v := range r.Options {
			if k == "" {
				return fmt.Errorf("options keys must be non-empty")
			}
			if containsLineBreak(k) || containsLineBreak(v) {
				return fmt.Errorf("options must not contain line breaks")
			}
		}
		return nil
	})
	if err != nil {
		return badRequest(c, err.Error())
	}
	script := tools.MetasploitScript(req)
	rcFile, err := executor.WriteTemp("msf", script)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer os.Remove(rcFile)
	args := tools.MetasploitArgs(rcFile)
	return c.JSON(toAPIResult(executor.RunExec(c.Context(), 0, args[0], args[1:]...)))
}

func handleHydra(c fiber.Ctx) error {
	return runTool(c, validateHydraRequest, tools.HydraArgs)
}

func handleHydraStream(c fiber.Ctx) error {
	return runToolStream(c, validateHydraRequest, tools.HydraArgs)
}

func handleJohn(c fiber.Ctx) error {
	return runTool(c, func(req dto.JohnRequest) error {
		if req.HashFile == "" {
			return fmt.Errorf("hash_file is required")
		}
		return nil
	}, tools.JohnArgs)
}

func handleHealth(c fiber.Ctx) error {
	status := toolStatus(executor.Which)
	allEssentialReady := allEssentialToolsAvailable(status)
	healthStatus := "healthy"
	message := "kali-server (Go/Fiber v3) running"
	if !allEssentialReady {
		healthStatus = "degraded"
		message = "kali-server (Go/Fiber v3) running with missing essential tools"
	}

	return c.JSON(dto.HealthResult{
		Status:                     healthStatus,
		Message:                    message,
		ToolsStatus:                status,
		AllEssentialToolsAvailable: allEssentialReady,
	})
}
