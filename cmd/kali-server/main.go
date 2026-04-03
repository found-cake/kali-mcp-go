package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

var essentialToolBinaries = []string{"nmap", "gobuster", "dirb", "nikto", "tshark"}

var exposedToolBinaries = []string{"nmap", "gobuster", "dirb", "nikto", "tshark", "sqlmap", "msfconsole", "hydra", "john", "wpscan", "enum4linux"}

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

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[kali-server] ")

	app := fiber.New(fiber.Config{
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  5 * time.Minute,
	})

	registerRoutes(app)

	addr := fmt.Sprintf("%s:%d", *ip, *port)
	log.Printf("listening on %s", addr)

	listenCfg := fiber.ListenConfig{
		DisableStartupMessage: !*debug,
		EnablePrintRoutes:     *debug,
	}
	log.Fatal(app.Listen(addr, listenCfg))
}

func registerRoutes(app *fiber.App) {
	app.Post("/api/command", handleCommand)
	app.Post("/api/command/stream", handleCommandStream)

	app.Post("/api/tools/nmap", handleNmap)
	app.Post("/api/tools/gobuster", handleGobuster)
	app.Post("/api/tools/dirb", handleDirb)
	app.Post("/api/tools/nikto", handleNikto)
	app.Post("/api/tools/tshark", handleTshark)
	app.Post("/api/tools/sqlmap", handleSQLMap)
	app.Post("/api/tools/metasploit", handleMetasploit)
	app.Post("/api/tools/hydra", handleHydra)
	app.Post("/api/tools/john", handleJohn)
	app.Post("/api/tools/wpscan", handleWPScan)
	app.Post("/api/tools/enum4linux", handleEnum4linux)

	app.Get("/health", handleHealth)
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
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, args)))
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
	if strings.TrimSpace(req.OutputFields) != "" {
		for field := range strings.SplitSeq(req.OutputFields, ",") {
			if strings.TrimSpace(field) != "" {
				return nil
			}
		}
		return fmt.Errorf("output_fields must contain at least one field")
	}
	return nil
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
	timeout := time.Duration(req.Timeout) * time.Second
	result := executor.Run(c.Context(), timeout, []string{req.Command})
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
	timeout := time.Duration(req.Timeout) * time.Second

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("X-Accel-Buffering", "no")

	lines, done := executor.Stream(c.Context(), timeout, []string{req.Command})

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
				return
			}
		}
		if result := <-done; result != nil {
			doneEvent := dto.StreamEvent{Done: true, ReturnCode: result.ReturnCode, TimedOut: result.TimedOut}
			if terminalErr := terminalStreamError(result, streamedStderr.String()); terminalErr != "" {
				doneEvent.Error = terminalErr
			}
			payload, _ := json.Marshal(doneEvent)
			fmt.Fprintf(w, "data: %s\n\n", payload)
			w.Flush()
		}
	})
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

func handleDirb(c fiber.Ctx) error {
	return runTool(c, func(req dto.DirbRequest) error {
		if req.URL == "" {
			return fmt.Errorf("url is required")
		}
		return nil
	}, tools.DirbArgs)
}

func handleNikto(c fiber.Ctx) error {
	return runTool(c, func(req dto.NiktoRequest) error {
		if req.Target == "" {
			return fmt.Errorf("target is required")
		}
		return nil
	}, tools.NiktoArgs)
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
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.MetasploitArgs(rcFile))))
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

func handleWPScan(c fiber.Ctx) error {
	return runTool(c, func(req dto.WPScanRequest) error {
		if req.URL == "" {
			return fmt.Errorf("url is required")
		}
		return nil
	}, tools.WPScanArgs)
}

func handleEnum4linux(c fiber.Ctx) error {
	return runTool(c, func(req dto.Enum4linuxRequest) error {
		if req.Target == "" {
			return fmt.Errorf("target is required")
		}
		return nil
	}, tools.Enum4linuxArgs)
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
