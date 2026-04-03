package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

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

func handleCommand(c fiber.Ctx) error {
	var req dto.CommandRequest
	if err := bindJSON(c, &req); err != nil || req.Command == "" {
		return badRequest(c, "command is required")
	}
	timeout := time.Duration(req.Timeout) * time.Second
	result := executor.Run(c.Context(), timeout, []string{req.Command})
	return c.JSON(toAPIResult(result))
}

func handleCommandStream(c fiber.Ctx) error {
	var req dto.CommandRequest
	if err := bindJSON(c, &req); err != nil || req.Command == "" {
		return badRequest(c, "command is required")
	}
	timeout := time.Duration(req.Timeout) * time.Second

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("X-Accel-Buffering", "no")

	lines, done := executor.Stream(c.Context(), timeout, []string{req.Command})

	return c.SendStreamWriter(func(w *bufio.Writer) {
		for line := range lines {
			payload, _ := json.Marshal(dto.StreamEvent{Stream: line.Stream, Line: line.Text})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			if err := w.Flush(); err != nil {
				return
			}
		}
		if result := <-done; result != nil {
			payload, _ := json.Marshal(dto.StreamEvent{Done: true, ReturnCode: result.ReturnCode, TimedOut: result.TimedOut})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			w.Flush()
		}
	})
}

func handleNmap(c fiber.Ctx) error {
	var req dto.NmapRequest
	if err := bindJSON(c, &req); err != nil || req.Target == "" {
		return badRequest(c, "target is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.NmapArgs(req))))
}

func handleGobuster(c fiber.Ctx) error {
	var req dto.GobusterRequest
	if err := bindJSON(c, &req); err != nil || req.URL == "" {
		return badRequest(c, "url is required")
	}
	if !tools.ValidGobusterMode(req.Mode) {
		return badRequest(c, "mode must be dir|dns|fuzz|vhost")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.GobusterArgs(req))))
}

func handleDirb(c fiber.Ctx) error {
	var req dto.DirbRequest
	if err := bindJSON(c, &req); err != nil || req.URL == "" {
		return badRequest(c, "url is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.DirbArgs(req))))
}

func handleNikto(c fiber.Ctx) error {
	var req dto.NiktoRequest
	if err := bindJSON(c, &req); err != nil || req.Target == "" {
		return badRequest(c, "target is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.NiktoArgs(req))))
}

func handleSQLMap(c fiber.Ctx) error {
	var req dto.SQLMapRequest
	if err := bindJSON(c, &req); err != nil || req.URL == "" {
		return badRequest(c, "url is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.SQLMapArgs(req))))
}

func handleMetasploit(c fiber.Ctx) error {
	var req dto.MetasploitRequest
	if err := bindJSON(c, &req); err != nil || req.Module == "" {
		return badRequest(c, "module is required")
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
	var req dto.HydraRequest
	if err := bindJSON(c, &req); err != nil || req.Target == "" || req.Service == "" {
		return badRequest(c, "target and service are required")
	}
	if req.Username == "" && req.UsernameFile == "" {
		return badRequest(c, "username or username_file is required")
	}
	if req.Password == "" && req.PasswordFile == "" {
		return badRequest(c, "password or password_file is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.HydraArgs(req))))
}

func handleJohn(c fiber.Ctx) error {
	var req dto.JohnRequest
	if err := bindJSON(c, &req); err != nil || req.HashFile == "" {
		return badRequest(c, "hash_file is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.JohnArgs(req))))
}

func handleWPScan(c fiber.Ctx) error {
	var req dto.WPScanRequest
	if err := bindJSON(c, &req); err != nil || req.URL == "" {
		return badRequest(c, "url is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.WPScanArgs(req))))
}

func handleEnum4linux(c fiber.Ctx) error {
	var req dto.Enum4linuxRequest
	if err := bindJSON(c, &req); err != nil || req.Target == "" {
		return badRequest(c, "target is required")
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, tools.Enum4linuxArgs(req))))
}

func handleHealth(c fiber.Ctx) error {
	essentials := []string{"nmap", "gobuster", "dirb", "nikto"}
	status := make(map[string]bool, len(essentials))
	allOK := true
	for _, t := range essentials {
		ok := executor.Which(t)
		status[t] = ok
		if !ok {
			allOK = false
		}
	}
	return c.JSON(dto.HealthResult{
		Status:                     "healthy",
		Message:                    "kali-server (Go/Fiber v3) running",
		ToolsStatus:                status,
		AllEssentialToolsAvailable: allOK,
	})
}
