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

	api.Post("/command", httpapi.WithExecutionLimit(limiter, handleCommand))
	api.Post("/command/stream", httpapi.WithExecutionLimit(limiter, handleCommandStream))
	api.Get("/tools/capabilities", handleScanCapabilities)
	api.Post("/tools/resolve-target", httpapi.WithExecutionLimit(limiter, handleResolveTarget))
	api.Post("/tools/http-request", httpapi.WithExecutionLimit(limiter, handleHTTPRequest))
	api.Get("/artifacts/:id", httpapi.HandleGetArtifact)
	api.Get("/artifacts/:id/page", httpapi.HandleGetArtifactPage)

	api.Post("/tools/gobuster", httpapi.WithExecutionLimit(limiter, handleGobuster))
	api.Post("/tools/gobuster/stream", httpapi.WithExecutionLimit(limiter, handleGobusterStream))
	api.Post("/tools/nmap/stream", httpapi.WithExecutionLimit(limiter, handleNmapStream))
	api.Post("/tools/dirb/stream", httpapi.WithExecutionLimit(limiter, handleDirbStream))
	api.Post("/tools/nikto/stream", httpapi.WithExecutionLimit(limiter, handleNiktoStream))
	api.Post("/tools/wpscan/stream", httpapi.WithExecutionLimit(limiter, handleWPScanStream))
	api.Post("/tools/enum4linux/stream", httpapi.WithExecutionLimit(limiter, handleEnum4linuxStream))
	api.Post("/tools/sqlmap/stream", httpapi.WithExecutionLimit(limiter, handleSQLMapStream))
	api.Post("/tools/tshark/stream", httpapi.WithExecutionLimit(limiter, handleTsharkStream))
	api.Post("/tools/metasploit", httpapi.WithExecutionLimit(limiter, handleMetasploit))
	api.Post("/tools/hydra", httpapi.WithExecutionLimit(limiter, handleHydra))
	api.Post("/tools/hydra/stream", httpapi.WithExecutionLimit(limiter, handleHydraStream))
	api.Post("/tools/john", httpapi.WithExecutionLimit(limiter, handleJohn))
	api.Post("/tools/ffuf/stream", httpapi.WithExecutionLimit(limiter, handleFFUFStream))
	api.Post("/tools/feroxbuster/stream", httpapi.WithExecutionLimit(limiter, handleFeroxbusterStream))
	api.Post("/tools/nuclei/stream", httpapi.WithExecutionLimit(limiter, handleNucleiStream))
	api.Post("/tools/whatweb/stream", httpapi.WithExecutionLimit(limiter, handleWhatWebStream))
	api.Post("/tools/jwt/stream", httpapi.WithExecutionLimit(limiter, handleJWTStream))
	api.Post("/tools/dalfox/stream", httpapi.WithExecutionLimit(limiter, handleDalfoxStream))
	api.Post("/tools/browser/stream", httpapi.WithExecutionLimit(limiter, handleBrowserStream))
	api.Post("/tools/retire/stream", httpapi.WithExecutionLimit(limiter, handleRetireStream))
	api.Post("/tools/osv/stream", httpapi.WithExecutionLimit(limiter, handleOSVStream))

	app.Get("/health", handleHealth)
}
