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
	result.CallID = callIDFromContext(c)
	protectResult(artifactStoreFromContext(c), result, req)
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
	lines = protectStream(execCtx, lines, req)
	callID := callIDFromContext(c)
	artifacts := artifactStoreFromContext(c)
	done = annotateResult(done, func(result *executor.Result) {
		result.CallID = callID
		protectResult(artifacts, result, req)
	})
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release)
}

func handleNmapStream(c fiber.Ctx) error {
	return runToolStream(c, validateNmapRequest, tools.NmapArgs)
}

func handleGobuster(c fiber.Ctx) error {
	return runTool(c, validateGobusterRequest, tools.GobusterArgs)
}

func handleGobusterStream(c fiber.Ctx) error {
	return runToolStream(c, validateGobusterRequest, tools.GobusterArgs)
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
	result := executor.RunExec(c.Context(), 0, args[0], args[1:]...)
	result.CallID = callIDFromContext(c)
	protectResult(artifactStoreFromContext(c), result, req)
	return c.JSON(toAPIResult(result))
}

func handleHydra(c fiber.Ctx) error {
	return runTool(c, validateHydraRequest, tools.HydraArgs)
}

func handleHydraStream(c fiber.Ctx) error {
	return runToolStream(c, validateHydraRequest, tools.HydraArgs)
}

func handleJohn(c fiber.Ctx) error {
	req, err := parseRequest(c, validateJohnRequest)
	if err != nil {
		return badRequest(c, err.Error())
	}
	plan, err := tools.PrepareJohn(req)
	if err != nil {
		return badRequest(c, err.Error())
	}
	defer plan.Cleanup()
	args := plan.Args()
	result := executor.RunExec(c.Context(), commandTimeout(req.Timeout), args[0], args[1:]...)
	result.CallID = callIDFromContext(c)
	if req.MaskPlaintext {
		result.Stdout = tools.RedactJohnOutput(result.Stdout)
		result.Stderr = tools.RedactJohnOutput(result.Stderr)
	}
	protectResult(artifactStoreFromContext(c), result, req)
	return c.JSON(toAPIResult(result))
}

func handleFeroxbusterStream(c fiber.Ctx) error {
	return runToolStream(c, validateFeroxbusterRequest, tools.FeroxbusterArgs)
}

func handleNucleiStream(c fiber.Ctx) error {
	return runToolStream(c, validateNucleiRequest, tools.NucleiArgs)
}

func handleWhatWebStream(c fiber.Ctx) error {
	return runToolStream(c, validateWhatWebRequest, tools.WhatWebArgs)
}

func handleJWTStream(c fiber.Ctx) error {
	return runToolStream(c, validateJWTRequest, tools.JWTToolArgs)
}

func handleDalfoxStream(c fiber.Ctx) error {
	return runToolStream(c, validateDalfoxRequest, tools.DalfoxArgs)
}

func handleBrowserStream(c fiber.Ctx) error {
	return runToolStream(c, validateBrowserRequest, tools.BrowserArgs)
}

func handleRetireStream(c fiber.Ctx) error {
	req, err := parseRequest(c, validateRetireRequest)
	if err != nil {
		return badRequest(c, err.Error())
	}
	scanPlan, err := prepareScanExecution(c, req, []string{"retire"})
	if err != nil {
		return scanPreparationError(c, err)
	}
	retirePlan, err := tools.PrepareRetire(c.Context(), req)
	if err != nil {
		scanPlan.release()
		return badRequest(c, err.Error())
	}
	scanPlan.args = retirePlan.Args()
	execCtx, cancel := context.WithCancel(c.Context())
	lines, done := executor.StreamExec(execCtx, scanPlan.timeout, scanPlan.args[0], scanPlan.args[1:]...)
	lines = protectStream(execCtx, lines, req)
	done = annotateResult(done, func(result *executor.Result) {
		scanPlan.annotate(result)
	})
	release := retainExecutionLease(c)
	return sendToolStreamWithCancel(c, lines, done, cancel, release, scanPlan.release, retirePlan.Cleanup)
}

func handleOSVStream(c fiber.Ctx) error {
	return runToolStream(c, validateOSVRequest, tools.OSVArgs)
}

func annotateResult(done <-chan *executor.Result, annotate func(*executor.Result)) <-chan *executor.Result {
	annotated := make(chan *executor.Result, 1)
	go func() {
		defer close(annotated)
		result, ok := <-done
		if !ok {
			return
		}
		annotate(result)
		annotated <- result
	}()
	return annotated
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
		CallID:                     callIDFromContext(c),
		Status:                     healthStatus,
		Message:                    message,
		ToolsStatus:                status,
		AllEssentialToolsAvailable: allEssentialReady,
	})
}
