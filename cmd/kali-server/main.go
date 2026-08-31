package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/toolapi"
	"github.com/found-cake/kali-mcp-go/internal/admission"
	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const shutdownTimeout = 10 * time.Second

const readTimeout = 10 * time.Second

func main() {
	var (
		ip            = flag.String("ip", "127.0.0.1", "bind address")
		port          = flag.Int("port", 5000, "port")
		debug         = flag.Bool("debug", false, "verbose logging")
		maxConcurrent = flag.Int("max-concurrent", httpapi.DefaultMaxConcurrentExecutions, "maximum number of concurrent execution requests")
	)
	flag.Parse()
	apiToken := strings.TrimSpace(os.Getenv(dto.APITokenEnv))
	if apiToken == "" {
		log.Fatalf("%s must be set", dto.APITokenEnv)
	}
	if *maxConcurrent <= 0 {
		log.Fatalf("--max-concurrent must be a positive integer")
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[kali-server] ")

	app := newApp(apiToken, *debug, *maxConcurrent, log.Printf)

	addr := fmt.Sprintf("%s:%d", *ip, *port)
	log.Printf("listening on %s", addr)

	listenCfg := fiber.ListenConfig{
		DisableStartupMessage: !*debug,
		EnablePrintRoutes:     *debug,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Listen(addr, listenCfg)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
		if err := app.ShutdownWithTimeout(shutdownTimeout); err != nil {
			log.Fatalf("shutdown: %v", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("listen after shutdown: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatal(err)
		}
	}
}

func newApp(apiToken string, debug bool, maxConcurrentExecutions int, print httpapi.LogPrinter) *fiber.App {
	limiter := httpapi.NewExecutionLimiter(maxConcurrentExecutions)
	weightedCapacity := max(maxConcurrentExecutions, 3)
	scheduler := admission.NewScheduler(weightedCapacity, 3)
	artifacts, err := artifactstore.New()
	if err != nil {
		panic(err)
	}
	app := fiber.New(fiber.Config{
		ReadTimeout:  readTimeout,
		WriteTimeout: 0,
		IdleTimeout:  5 * time.Minute,
	})
	if debug {
		app.Use(httpapi.DebugRequestLogMiddleware(print))
	}
	app.Use(httpapi.CallTelemetryMiddleware(print))
	app.Use(httpapi.TargetSchedulerMiddleware(scheduler))
	app.Use(httpapi.ArtifactStoreMiddleware(artifacts))
	app.Hooks().OnPostShutdown(func(error) error { return artifacts.Close() })

	registerRoutes(app, apiToken, limiter)
	return app
}

func registerRoutes(app *fiber.App, apiToken string, limiter *admission.Limiter) {
	api := app.Group("/api", httpapi.BearerAuthMiddleware(apiToken))
	api.Get("/artifacts/:id", httpapi.HandleGetArtifact)
	api.Get("/artifacts/:id/page", httpapi.HandleGetArtifactPage)
	toolapi.Mount(app, api, limiter)
}
