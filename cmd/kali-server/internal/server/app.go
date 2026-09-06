package server

import (
	"context"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/toolapi"
	"github.com/found-cake/kali-mcp-go/internal/admission"
	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/jobs"
	"github.com/gofiber/fiber/v3"
)

const readTimeout = 10 * time.Second

func newApp(apiToken string, debug bool, maxConcurrentExecutions int, print httpapi.LogPrinter) *fiber.App {
	limiter := httpapi.NewExecutionLimiter(maxConcurrentExecutions)
	weightedCapacity := max(maxConcurrentExecutions, 3)
	scheduler := admission.NewScheduler(weightedCapacity, 3)
	artifacts, err := artifactstore.New()
	if err != nil {
		panic(err)
	}
	jobStore := jobs.New(context.Background())
	app := fiber.New(fiber.Config{
		ReadTimeout:  readTimeout,
		WriteTimeout: 0,
		IdleTimeout:  5 * time.Minute,
	})
	cancellations := httpapi.NewCallCancellationRegistry()
	if debug {
		app.Use(httpapi.DebugRequestLogMiddleware(print))
	}
	app.Use(httpapi.CallTelemetryMiddleware(print))
	app.Use(httpapi.CallCancellationRegistryMiddleware(cancellations))
	app.Use(httpapi.TargetSchedulerMiddleware(scheduler))
	app.Use(httpapi.ArtifactStoreMiddleware(artifacts))
	app.Use(httpapi.JobStoreMiddleware(jobStore))
	app.Hooks().OnPostShutdown(func(error) error {
		jobStore.Close()
		return artifacts.Close()
	})
	registerRoutes(app, apiToken, limiter)
	return app
}

func registerRoutes(app *fiber.App, apiToken string, limiter *admission.Limiter) {
	api := app.Group("/api", httpapi.BearerAuthMiddleware(apiToken))
	api.Get("/artifacts/:id", httpapi.HandleGetArtifact)
	api.Get("/artifacts/:id/page", httpapi.HandleGetArtifactPage)
	api.Post("/calls/:id/cancel", httpapi.HandleCancelCall)
	api.Get("/jobs/:id/status", httpapi.HandleJobStatus)
	api.Get("/jobs/:id/result", httpapi.HandleJobResult)
	api.Post("/jobs/:id/cancel", httpapi.HandleJobCancel)
	toolapi.Mount(app, api, limiter)
}
