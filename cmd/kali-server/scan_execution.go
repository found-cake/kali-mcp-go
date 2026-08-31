package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/admission"
	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

var healthHTTPClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	},
}

func scanPreparationError(c fiber.Ctx, err error) error {
	if errors.Is(err, admission.ErrGlobalCapacityExceeded) || errors.Is(err, admission.ErrTargetCapacityExceeded) {
		return httpapi.ServiceUnavailable(c, err.Error())
	}
	return httpapi.BadRequest(c, err.Error())
}

type scanExecutionPlan struct {
	callID                string
	args                  []string
	options               dto.ScanOptions
	controls              dto.ScanControlApplication
	target                *dto.TargetProvenance
	timeout               time.Duration
	timeoutPlanning       *dto.TimeoutPlanning
	release               func()
	healthURL             string
	request               any
	context               context.Context
	spaBaseline           *dto.SPABaseline
	falsePositiveRisk     string
	extraWarnings         []string
	artifactStore         *artifactstore.Store
	jwtAnalysis           *dto.JWTAnalysisMetadata
	browserScreenshotPath string
	dryRun                bool
}

func prepareScanExecution[T any](c fiber.Ctx, request T, args []string) (*scanExecutionPlan, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("internal error: no command generated")
	}
	options := dto.ScanOptions{}
	if scanRequest, ok := any(request).(dto.ScanRequest); ok {
		options = scanRequest.GetScanOptions()
	}
	effective, err := tools.EffectiveScanOptions(args[0], options)
	if err != nil {
		return nil, err
	}
	controlledArgs, err := tools.ApplyScanControls(args, effective)
	if err != nil {
		return nil, err
	}
	provenance, err := targeting.ResolveProvenance(request, httpapi.APIToken(c), time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if tools.RuntimeRequiresTargetContext(args[0]) && (provenance == nil || !provenance.Verified) {
		return nil, fmt.Errorf("%s requires a verified target_context from resolve_target", args[0])
	}
	if effective.HealthURL != "" {
		if err := probeTargetHealth(c.Context(), effective.HealthURL); err != nil {
			return nil, fmt.Errorf("pre-scan health check: %w", err)
		}
	}
	target := tools.RequestTarget(request)
	if provenance != nil {
		target = provenance.Selected
	}
	release := func() {}
	if scheduler := httpapi.Scheduler(c); scheduler != nil {
		release, err = scheduler.Acquire(target, scanWeight(controlledArgs[0]))
		if err != nil {
			return nil, err
		}
	}
	requestedTimeout := 0
	if timeoutRequest, ok := any(request).(dto.TimeoutRequest); ok {
		requestedTimeout = timeoutRequest.GetRequestTimeout()
	}
	dryRun := false
	if request, ok := any(request).(dto.DryRunRequest); ok {
		dryRun = request.GetDryRun()
	}
	timeout := commandTimeout(requestedTimeout)
	timeoutPlanning := &dto.TimeoutPlanning{Source: dto.TimeoutSourceDefault}
	if requestedTimeout > 0 {
		timeoutPlanning.Source = dto.TimeoutSourceRequest
	}
	if effective.MaxRequests > 0 && effective.RateLimit > 0 {
		budgetSeconds := (effective.MaxRequests + effective.RateLimit - 1) / effective.RateLimit
		budgetTimeout := time.Duration(budgetSeconds) * time.Second
		timeoutPlanning.RequestBudgetEstimateMS = budgetTimeout.Milliseconds()
		if requestedTimeout == 0 {
			startupGrace := 10 * time.Second
			switch controlledArgs[0] {
			case "ffuf", "nmap":
				startupGrace = 5 * time.Second
			case "feroxbuster":
				startupGrace = 10 * time.Second
			case "nuclei", "sqlmap":
				startupGrace = 30 * time.Second
			}
			timeout = budgetTimeout + startupGrace
			timeoutPlanning.Source = dto.TimeoutSourceRequestBudget
			timeoutPlanning.StartupGraceMS = startupGrace.Milliseconds()
		}
	}
	return &scanExecutionPlan{
		callID: httpapi.CallID(c),
		args:   controlledArgs, options: effective, target: provenance, timeout: timeout,
		controls: tools.ScanControlApplication(args[0], options, effective),
		release:  release, healthURL: effective.HealthURL, request: request, context: c.Context(),
		artifactStore:   httpapi.ArtifactStore(c),
		dryRun:          dryRun,
		timeoutPlanning: timeoutPlanning,
	}, nil
}

func (p *scanExecutionPlan) annotate(result *executor.Result) {
	result.CallID = p.callID
	result.Target = p.target
	result.Warnings = append(result.Warnings, targeting.Warnings(p.request, p.target)...)
	result.Policy = p.options
	result.Controls = p.controls
	result.JWTAnalysis = p.jwtAnalysis
	result.BrowserScreenshotPath = p.browserScreenshotPath
	result.SPABaseline = p.spaBaseline
	result.FalsePositiveRisk = p.falsePositiveRisk
	result.TimeoutPlanning = p.timeoutPlanning
	result.Warnings = append(result.Warnings, p.extraWarnings...)
	result.FinalizeProgress()
	if p.healthURL != "" {
		if err := probeTargetHealth(p.context, p.healthURL); err != nil {
			result.Warnings = append(result.Warnings, "post-scan health check failed: "+err.Error())
		}
	}
	results.Protect(p.artifactStore, result, p.request)
}

func probeTargetHealth(ctx context.Context, target string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}
	response, err := healthHTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("request health URL: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("health URL returned %d", response.StatusCode)
	}
	return nil
}
