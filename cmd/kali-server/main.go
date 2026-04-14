package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

var essentialToolBinaries = []string{"nmap", "gobuster", "dirb", "nikto", "tshark"}

var exposedToolBinaries = []string{"nmap", "gobuster", "dirb", "nikto", "tshark", "sqlmap", "msfconsole", "hydra", "john", "wpscan", "enum4linux"}

const shutdownTimeout = 10 * time.Second

type logPrinter func(format string, args ...any)

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

func terminalStreamError(result *executor.Result, streamedStderr string) string {
	if result == nil || result.ReturnCode == 0 || result.Stderr == "" {
		return ""
	}

	terminalErr := result.Stderr
	if streamedStderr != "" && strings.HasPrefix(terminalErr, streamedStderr) {
		terminalErr = strings.TrimPrefix(terminalErr, streamedStderr)
	}

	return strings.TrimLeft(terminalErr, "\n")
}

func main() {
	var (
		ip    = flag.String("ip", "127.0.0.1", "bind address")
		port  = flag.Int("port", 5000, "port")
		debug = flag.Bool("debug", false, "verbose logging")
	)
	flag.Parse()
	apiToken := strings.TrimSpace(os.Getenv(dto.APITokenEnv))
	if apiToken == "" {
		log.Fatalf("%s must be set", dto.APITokenEnv)
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[kali-server] ")

	app := newApp(apiToken, *debug, log.Printf)

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

func newApp(apiToken string, debug bool, print logPrinter) *fiber.App {
	app := fiber.New(fiber.Config{
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  5 * time.Minute,
	})
	if debug {
		app.Use(debugRequestLogMiddleware(print))
	}

	registerRoutes(app, apiToken)
	return app
}

func debugRequestLogMiddleware(print logPrinter) fiber.Handler {
	if print == nil {
		print = func(string, ...any) {}
	}

	return func(c fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		print("%s %s -> %d (%s)", c.Method(), c.Path(), c.Response().StatusCode(), time.Since(start).Round(time.Microsecond))
		return err
	}
}

func registerRoutes(app *fiber.App, apiToken string) {
	api := app.Group("/api", bearerAuthMiddleware(apiToken))

	api.Post("/command", handleCommand)
	api.Post("/command/stream", handleCommandStream)

	api.Post("/tools/nmap", handleNmap)
	api.Post("/tools/gobuster", handleGobuster)
	api.Post("/tools/dirb/stream", handleDirbStream)
	api.Post("/tools/nikto/stream", handleNiktoStream)
	api.Post("/tools/wpscan/stream", handleWPScanStream)
	api.Post("/tools/enum4linux/stream", handleEnum4linuxStream)
	api.Post("/tools/tshark", handleTshark)
	api.Post("/tools/sqlmap", handleSQLMap)
	api.Post("/tools/metasploit", handleMetasploit)
	api.Post("/tools/hydra", handleHydra)
	api.Post("/tools/john", handleJohn)

	app.Get("/health", handleHealth)
}

func bearerAuthMiddleware(apiToken string) fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing bearer token"})
		}
		providedToken := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
		providedSum := sha256.Sum256([]byte(providedToken))
		expectedSum := sha256.Sum256([]byte(apiToken))
		if subtle.ConstantTimeCompare(providedSum[:], expectedSum[:]) != 1 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid bearer token"})
		}
		return c.Next()
	}
}

func toAPIResult(r *executor.Result) dto.ToolResult {
	return dto.ToolResult{
		Stdout:         r.Stdout,
		Stderr:         r.Stderr,
		ReturnCode:     r.ReturnCode,
		Success:        r.Success(),
		TimedOut:       r.TimedOut,
		PartialResults: r.TimedOut && (r.Stdout != "" || r.Stderr != ""),
	}
}

func badRequest(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
}

func internalServerError(c fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": msg})
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

func containsLineBreak(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

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

func runToolStream[T any](c fiber.Ctx, validate func(T) error, argsFor func(T) ([]string, error)) error {
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
	lines, done := executor.StreamExec(c.Context(), 0, args[0], args[1:]...)
	return sendToolStream(c, lines, done)
}

func validatePositiveInt(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fmt.Errorf("%s must be a positive integer", name)
	}
	return nil
}

func validateTsharkRequest(req dto.TsharkRequest) error {
	readFile := strings.TrimSpace(req.ReadFile)
	iface := strings.TrimSpace(req.Interface)
	switch {
	case readFile == "" && iface == "":
		return fmt.Errorf("read_file or interface is required")
	case readFile != "" && iface != "":
		return fmt.Errorf("read_file and interface cannot be used together")
	}
	if err := validatePositiveInt("packet_count", req.PacketCount); err != nil {
		return err
	}
	if err := validatePositiveInt("duration", req.Duration); err != nil {
		return err
	}
	if strings.TrimSpace(req.OutputFields) != "" && !hasNonEmptyCSVField(req.OutputFields) {
		return fmt.Errorf("output_fields must contain at least one field")
	}
	return nil
}

func hasNonEmptyCSVField(value string) bool {
	for field := range strings.SplitSeq(value, ",") {
		if strings.TrimSpace(field) != "" {
			return true
		}
	}
	return false
}

func commandTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return dto.DefaultTimeout
	}
	return time.Duration(seconds) * time.Second
}

func sendToolStream(c fiber.Ctx, lines <-chan executor.Line, done <-chan *executor.Result) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("X-Accel-Buffering", "no")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		var streamedStderr strings.Builder
		for line := range lines {
			if line.Stream == "stderr" {
				streamedStderr.WriteString(line.Text)
				streamedStderr.WriteByte('\n')
			}
			payload, _ := json.Marshal(dto.StreamEvent{Stream: line.Stream, Line: line.Text})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			if err := w.Flush(); err != nil {
				for range lines {
				}
				return
			}
		}
		result := <-done
		returnCode := result.ReturnCode
		doneEvent := dto.StreamEvent{Done: true, ReturnCode: &returnCode, TimedOut: result.TimedOut}
		if terminalErr := terminalStreamError(result, streamedStderr.String()); terminalErr != "" {
			doneEvent.Error = terminalErr
		}
		payload, _ := json.Marshal(doneEvent)
		fmt.Fprintf(w, "data: %s\n\n", payload)
		_ = w.Flush()
	})
}

func validateHydraRequest(req dto.HydraRequest) error {
	if req.Target == "" || req.Service == "" {
		return fmt.Errorf("target and service are required")
	}
	if req.Username != "" && req.UsernameFile != "" {
		return fmt.Errorf("username and username_file cannot be used together")
	}
	if req.Password != "" && req.PasswordFile != "" {
		return fmt.Errorf("password and password_file cannot be used together")
	}
	if req.Username == "" && req.UsernameFile == "" {
		return fmt.Errorf("username or username_file is required")
	}
	if req.Password == "" && req.PasswordFile == "" {
		return fmt.Errorf("password or password_file is required")
	}
	return nil
}

func validateNiktoRequest(req dto.NiktoRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

func validateDirbRequest(req dto.DirbRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}

func validateWPScanRequest(req dto.WPScanRequest) error {
	if req.URL == "" {
		return fmt.Errorf("url is required")
	}
	return nil
}

func validateEnum4linuxRequest(req dto.Enum4linuxRequest) error {
	if req.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
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
	lines, done := executor.StreamShell(c.Context(), timeout, req.Command)
	return sendToolStream(c, lines, done)
}

func handleNmap(c fiber.Ctx) error {
	return runTool(c, func(req dto.NmapRequest) error {
		if req.Target == "" {
			return fmt.Errorf("target is required")
		}
		return nil
	}, tools.NmapArgs)
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

func handleTshark(c fiber.Ctx) error {
	return runTool(c, validateTsharkRequest, tools.TsharkArgs)
}

func handleSQLMap(c fiber.Ctx) error {
	return runTool(c, func(req dto.SQLMapRequest) error {
		if req.URL == "" {
			return fmt.Errorf("url is required")
		}
		return nil
	}, tools.SQLMapArgs)
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
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer os.Remove(rcFile)
	args := tools.MetasploitArgs(rcFile)
	return c.JSON(toAPIResult(executor.RunExec(c.Context(), 0, args[0], args[1:]...)))
}

func handleHydra(c fiber.Ctx) error {
	return runTool(c, validateHydraRequest, tools.HydraArgs)
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
