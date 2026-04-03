package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
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

func runTool[T any](c fiber.Ctx, validate func(T) error, argsFor func(T) []string) error {
	req, err := parseRequest(c, validate)
	if err != nil {
		return badRequest(c, err.Error())
	}
	return c.JSON(toAPIResult(executor.Run(c.Context(), 0, argsFor(req))))
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
	return runTool(c, func(dto.TsharkRequest) error {
		return nil
	}, tools.TsharkArgs)
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
	return runTool(c, func(req dto.HydraRequest) error {
		if req.Target == "" || req.Service == "" {
			return fmt.Errorf("target and service are required")
		}
		if req.Username == "" && req.UsernameFile == "" {
			return fmt.Errorf("username or username_file is required")
		}
		if req.Password == "" && req.PasswordFile == "" {
			return fmt.Errorf("password or password_file is required")
		}
		return nil
	}, tools.HydraArgs)
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
	essentials := []string{"nmap", "gobuster", "dirb", "nikto", "tshark"}
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
