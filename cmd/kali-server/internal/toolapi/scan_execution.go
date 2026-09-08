package toolapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
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
	CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("health URL stopped after 10 redirects")
		}
		if len(via) > 0 {
			origin, originOK := targeting.Origin(via[0].URL.String())
			destination, destinationOK := targeting.Origin(request.URL.String())
			if !originOK || !destinationOK || origin != destination {
				return errors.New("health URL redirect changes origin")
			}
		}
		return nil
	},
}

func scanPreparationError(c fiber.Ctx, err error) error {
	if errors.Is(err, httpapi.ErrCallIDAlreadyActive) {
		return httpapi.Conflict(c, err.Error())
	}
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
	release               func()
	healthURL             string
	request               any
	context               context.Context
	spaBaseline           *dto.SPABaseline
	falsePositiveRisk     string
	extraWarnings         []string
	artifactStore         *artifactstore.Store
	jwtAnalysis           *dto.JWTAnalysisMetadata
	nucleiPreview         *dto.NucleiPreviewMetadata
	browserScreenshotPath string
	ephemeralPaths        []string
	dryRun                bool
	async                 bool
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
	dryRun := false
	if request, ok := any(request).(dto.DryRunRequest); ok {
		dryRun = request.GetDryRun()
	}
	async := httpapi.AsyncRequested(c)
	if async && dryRun {
		return nil, fmt.Errorf("async and dry_run cannot be combined")
	}
	provenance, err := targeting.ResolveProvenance(request, httpapi.APIToken(c), time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if tools.RuntimeRequiresTargetContext(args[0]) && (provenance == nil || !provenance.Verified) {
		return nil, fmt.Errorf("%s requires a verified target_context from resolve_target", args[0])
	}
	if err := targeting.ValidateHealthURL(effective.HealthURL, provenance); err != nil {
		return nil, err
	}
	if effective.HealthURL != "" && !dryRun {
		if err := probeTargetHealth(c.Context(), effective.HealthURL); err != nil {
			return nil, fmt.Errorf("pre-scan health check: %w", err)
		}
	}
	target := tools.RequestTarget(request)
	if provenance != nil {
		target = provenance.Selected
	}
	schedulerTarget := targeting.SchedulerKey(target, provenance)
	release := func() {}
	if scheduler := httpapi.Scheduler(c); scheduler != nil {
		release, err = scheduler.Acquire(schedulerTarget, scanWeight(controlledArgs[0]))
		if err != nil {
			return nil, err
		}
	}
	requestedTimeout := 0
	if timeoutRequest, ok := any(request).(dto.TimeoutRequest); ok {
		requestedTimeout = timeoutRequest.GetRequestTimeout()
	}
	timeout := commandTimeout(requestedTimeout)
	extraWarnings := []string(nil)
	if nucleiRequest, ok := any(request).(dto.NucleiRequest); ok && strings.TrimSpace(nucleiRequest.Tags) == "" && len(nucleiRequest.Templates) == 0 {
		extraWarnings = append(extraWarnings, "Nuclei tags or templates were not selected; all locally installed safe templates may be evaluated")
	}
	return &scanExecutionPlan{
		callID: httpapi.CallID(c),
		args:   controlledArgs, options: effective, target: provenance, timeout: timeout,
		controls: tools.ScanControlApplication(args[0], options, effective),
		release:  release, healthURL: effective.HealthURL, request: request, context: c.Context(),
		artifactStore: httpapi.ArtifactStore(c),
		dryRun:        dryRun,
		async:         async,
		extraWarnings: extraWarnings,
	}, nil
}

func (p *scanExecutionPlan) annotate(result *executor.Result) {
	result.CallID = p.callID
	result.Target = p.target
	result.Warnings = append(result.Warnings, targeting.Warnings(p.request, p.target)...)
	result.Policy = p.options
	result.Controls = p.controls
	result.JWTAnalysis = p.jwtAnalysis
	result.NucleiPreview = p.nucleiPreview
	result.BrowserScreenshotPath = p.browserScreenshotPath
	result.SPABaseline = p.spaBaseline
	result.FalsePositiveRisk = p.falsePositiveRisk
	result.Warnings = append(result.Warnings, p.extraWarnings...)
	result.FinalizeProgress()
	results.HideImplementationPaths(result, p.ephemeralPaths...)
	if p.healthURL != "" && !p.dryRun {
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
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("request health URL: %w", err)
	}
	if response.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("health URL returned %d", response.StatusCode)
	}
	return nil
}
