package toolapi

import (
	"context"
	"fmt"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleCommand(c fiber.Ctx) error {
	req, err := httpapi.ParseRequest(c, func(r dto.CommandRequest) error {
		if r.Command == "" {
			return fmt.Errorf("command is required")
		}
		return nil
	})
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	timeout := commandTimeout(req.Timeout)
	result := executor.RunShell(c.Context(), timeout, req.Command)
	result.CallID = httpapi.CallID(c)
	return httpapi.WriteToolResult(c, result, req)
}

func handleCommandStream(c fiber.Ctx) error {
	req, err := httpapi.ParseRequest(c, func(r dto.CommandRequest) error {
		if r.Command == "" {
			return fmt.Errorf("command is required")
		}
		return nil
	})
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	timeout := commandTimeout(req.Timeout)
	plan := &scanExecutionPlan{
		callID: httpapi.CallID(c), args: []string{"bash", "-c", req.Command},
		timeout: timeout, release: func() {}, request: req, context: c.Context(),
		artifactStore: httpapi.ArtifactStore(c), async: httpapi.AsyncRequested(c),
	}
	return executeToolStream(c, streamExecution{
		plan: plan,
		launch: func(ctx context.Context) (<-chan executor.Line, <-chan *executor.Result) {
			return executor.StreamShell(ctx, timeout, req.Command)
		},
	})
}

func handleNmapStream(c fiber.Ctx) error {
	return runToolStream(c, validateNmapRequest, tools.NmapArgs)
}

func handleGobuster(c fiber.Ctx) error {
	return withPreparedTool(c, gobusterExecutionSpec(), func(plan *scanExecutionPlan) error {
		defer plan.release()
		if plan.async {
			return httpapi.BadRequest(c, "asynchronous execution requires a streaming tool route")
		}
		result := executeOrPreview(c.Context(), plan)
		plan.annotate(result)
		return c.JSON(results.ToToolResult(result))
	})
}

func handleGobusterStream(c fiber.Ctx) error {
	return withPreparedTool(c, gobusterExecutionSpec(), func(plan *scanExecutionPlan) error {
		return executeStreamPlan(c, plan)
	})
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

func handleHydra(c fiber.Ctx) error {
	return runTool(c, validateHydraRequest, tools.HydraArgs)
}

func handleHydraStream(c fiber.Ctx) error {
	return runToolStream(c, validateHydraRequest, tools.HydraArgs)
}

func handleJohn(c fiber.Ctx) error {
	req, err := httpapi.ParseRequest(c, validateJohnRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	plan, err := tools.PrepareJohn(req)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	args := plan.Args()
	timeout := commandTimeout(req.Timeout)
	if httpapi.AsyncRequested(c) {
		executionPlan := &scanExecutionPlan{
			callID: httpapi.CallID(c), args: args, timeout: timeout,
			release: plan.Cleanup, request: req, context: c.Context(),
			artifactStore: httpapi.ArtifactStore(c), ephemeralPaths: []string{plan.EphemeralPath()}, async: true,
		}
		return executeAsyncTool(c, streamExecution{
			plan: executionPlan, tool: "john",
			beforeAnnotate: func(result *executor.Result) {
				if req.MaskPlaintext {
					result.Stdout = tools.RedactJohnOutput(result.Stdout)
					result.Stderr = tools.RedactJohnOutput(result.Stderr)
				}
			},
		})
	}
	defer plan.Cleanup()
	result := executor.RunExec(c.Context(), timeout, args[0], args[1:]...)
	result.CallID = httpapi.CallID(c)
	if req.MaskPlaintext {
		result.Stdout = tools.RedactJohnOutput(result.Stdout)
		result.Stderr = tools.RedactJohnOutput(result.Stderr)
	}
	results.HideImplementationPaths(result, plan.EphemeralPath())
	return httpapi.WriteToolResult(c, result, req)
}

func handleNucleiStream(c fiber.Ctx) error {
	return withPreparedTool(c, toolExecutionSpec[dto.NucleiRequest]{
		validate: validateNucleiRequest,
		argsFor:  tools.NucleiArgs,
		decorate: decorateNucleiExecution,
	}, func(plan *scanExecutionPlan) error {
		return executeStreamPlan(c, plan)
	})
}

func handleWhatWebStream(c fiber.Ctx) error {
	return runToolStream(c, validateWhatWebRequest, tools.WhatWebArgs)
}

func handleJWTStream(c fiber.Ctx) error {
	return withPreparedTool(c, toolExecutionSpec[dto.JWTRequest]{
		validate: validateJWTRequest,
		argsFor:  tools.JWTToolArgs,
		decorate: func(request dto.JWTRequest, plan *scanExecutionPlan) error {
			analysis := tools.AnalyzeJWTStructure(request.Token)
			plan.jwtAnalysis = &analysis
			return nil
		},
	}, func(plan *scanExecutionPlan) error {
		return executeStreamPlan(c, plan)
	})
}

func handleDalfoxStream(c fiber.Ctx) error {
	return runToolStream(c, validateDalfoxRequest, tools.DalfoxArgs)
}

func handleRetireStream(c fiber.Ctx) error {
	req, err := httpapi.ParseRequest(c, validateRetireRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	scanPlan, err := prepareScanExecution(c, req, []string{"retire"})
	if err != nil {
		return scanPreparationError(c, err)
	}
	retirePlan, err := tools.PrepareRetire(c.Context(), req)
	if err != nil {
		scanPlan.release()
		return httpapi.BadRequest(c, err.Error())
	}
	scanPlan.args = retirePlan.Args()
	scanPlan.ephemeralPaths = []string{retirePlan.EphemeralPath()}
	return executeToolStream(c, streamExecution{
		plan: scanPlan, cleanups: []func(){retirePlan.Cleanup},
	})
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

func handleScanCapabilities(c fiber.Ctx) error {
	result := tools.ScanCapabilities(executor.Which)
	result.CallID = httpapi.CallID(c)
	return c.JSON(result)
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
		CallID:                     httpapi.CallID(c),
		Status:                     healthStatus,
		Message:                    message,
		ToolsStatus:                status,
		AllEssentialToolsAvailable: allEssentialReady,
	})
}
