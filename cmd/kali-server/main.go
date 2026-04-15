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

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

var essentialToolBinaries = []string{"nmap", "gobuster", "dirb", "nikto", "tshark"}

var exposedToolBinaries = []string{"nmap", "gobuster", "dirb", "nikto", "tshark", "sqlmap", "msfconsole", "hydra", "john", "wpscan", "enum4linux"}

const shutdownTimeout = 10 * time.Second

const streamHeartbeatInterval = 15 * time.Second

const readTimeout = 10 * time.Second

type logPrinter func(format string, args ...any)

func main() {
	var (
		ip            = flag.String("ip", "127.0.0.1", "bind address")
		port          = flag.Int("port", 5000, "port")
		debug         = flag.Bool("debug", false, "verbose logging")
		maxConcurrent = flag.Int("max-concurrent", defaultMaxConcurrentExecutions, "maximum number of concurrent execution requests")
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

func newApp(apiToken string, debug bool, maxConcurrentExecutions int, print logPrinter) *fiber.App {
	limiter := newExecutionLimiter(maxConcurrentExecutions)
	app := fiber.New(fiber.Config{
		ReadTimeout:  readTimeout,
		WriteTimeout: 0,
		IdleTimeout:  5 * time.Minute,
	})
	if debug {
		app.Use(debugRequestLogMiddleware(print))
	}

	registerRoutes(app, apiToken, limiter)
	return app
}

func registerRoutes(app *fiber.App, apiToken string, limiter *executionLimiter) {
	api := app.Group("/api", bearerAuthMiddleware(apiToken))

	api.Post("/command", withExecutionLimit(limiter, handleCommand))
	api.Post("/command/stream", withExecutionLimit(limiter, handleCommandStream))

	api.Post("/tools/gobuster", withExecutionLimit(limiter, handleGobuster))
	api.Post("/tools/nmap/stream", withExecutionLimit(limiter, handleNmapStream))
	api.Post("/tools/dirb/stream", withExecutionLimit(limiter, handleDirbStream))
	api.Post("/tools/nikto/stream", withExecutionLimit(limiter, handleNiktoStream))
	api.Post("/tools/wpscan/stream", withExecutionLimit(limiter, handleWPScanStream))
	api.Post("/tools/enum4linux/stream", withExecutionLimit(limiter, handleEnum4linuxStream))
	api.Post("/tools/sqlmap/stream", withExecutionLimit(limiter, handleSQLMapStream))
	api.Post("/tools/tshark/stream", withExecutionLimit(limiter, handleTsharkStream))
	api.Post("/tools/metasploit", withExecutionLimit(limiter, handleMetasploit))
	api.Post("/tools/hydra", withExecutionLimit(limiter, handleHydra))
	api.Post("/tools/hydra/stream", withExecutionLimit(limiter, handleHydraStream))
	api.Post("/tools/john", withExecutionLimit(limiter, handleJohn))

	app.Get("/health", handleHealth)
}
