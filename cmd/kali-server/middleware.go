package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

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
		return c.Next()
	}
}
