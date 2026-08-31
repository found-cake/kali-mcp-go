package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const (
	apiTokenLocalKey = "api-token"
	callIDLocalKey   = "call-id"
)

type callTelemetryRecord struct {
	CallID     string    `json:"call_id"`
	Operation  string    `json:"operation"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	DurationMS int64     `json:"duration_ms"`
	HTTPStatus int       `json:"http_status"`
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
		c.Locals(apiTokenLocalKey, apiToken)
		return c.Next()
	}
}

func apiTokenFromContext(c fiber.Ctx) string {
	value, _ := c.Locals(apiTokenLocalKey).(string)
	return value
}

func callTelemetryMiddleware(print logPrinter) fiber.Handler {
	if print == nil {
		print = func(string, ...any) {}
	}
	return func(c fiber.Ctx) error {
		callID, err := randomCallID()
		if err != nil {
			return internalServerError(c, "failed to generate call ID")
		}
		startedAt := time.Now().UTC()
		c.Locals(callIDLocalKey, callID)
		c.Set(dto.CallIDHeader, callID)
		handlerErr := c.Next()
		endedAt := time.Now().UTC()
		record := callTelemetryRecord{
			CallID: callID, Operation: callOperation(c.Path()), Method: c.Method(), Path: c.Path(),
			StartedAt: startedAt, EndedAt: endedAt,
			DurationMS: endedAt.Sub(startedAt).Milliseconds(), HTTPStatus: c.Response().StatusCode(),
		}
		if payload, marshalErr := json.Marshal(record); marshalErr == nil {
			print("%s", payload)
		}
		return handlerErr
	}
}

func randomCallID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "call_" + hex.EncodeToString(raw), nil
}

func callIDFromContext(c fiber.Ctx) string {
	callID, _ := c.Locals(callIDLocalKey).(string)
	return callID
}

func callOperation(path string) string {
	trimmed := strings.Trim(strings.TrimPrefix(path, "/api/"), "/")
	switch {
	case trimmed == "command" || trimmed == "command/stream":
		return "execute_command"
	case strings.HasPrefix(trimmed, "artifacts/"):
		return "result_artifact_read"
	case trimmed == "tools/capabilities":
		return "get_scan_capabilities"
	case trimmed == "tools/resolve-target":
		return "resolve_target"
	case trimmed == "tools/http-request":
		return "http_request"
	case strings.HasPrefix(trimmed, "tools/"):
		name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "tools/"), "/stream")
		switch name {
		case "wpscan":
			return "wpscan_analyze"
		case "tshark":
			return "tshark_capture"
		case "metasploit":
			return "metasploit_run"
		case "hydra":
			return "hydra_attack"
		case "john":
			return "john_crack"
		case "jwt":
			return "jwt_analyze"
		case "browser":
			return "browser_check"
		case "retire":
			return "retirejs_scan"
		}
		return strings.ReplaceAll(name, "-", "_") + "_scan"
	case trimmed == "health":
		return "server_health"
	default:
		return strings.ReplaceAll(trimmed, "/", "_")
	}
}
