package httpapi

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestBearerAuthPreservesHeaderContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header string
		status int
		body   string
	}{
		{"valid", "Bearer fixture-token", 200, "authorized"},
		{"trimmed", "  Bearer   fixture-token  ", 200, "authorized"},
		{"missing", "", 401, `{"error":"missing bearer token"}`},
		{"wrong scheme", "Basic fixture-token", 401, `{"error":"missing bearer token"}`},
		{"lowercase scheme", "bearer fixture-token", 401, `{"error":"missing bearer token"}`},
		{"empty token", "Bearer ", 401, `{"error":"missing bearer token"}`},
		{"wrong token", "Bearer other-token", 401, `{"error":"invalid bearer token"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			app := fiber.New()
			app.Use(BearerAuthMiddleware("fixture-token"))
			app.Get("/", func(c fiber.Ctx) error {
				if APIToken(c) != "fixture-token" {
					return c.SendStatus(http.StatusInternalServerError)
				}
				return c.SendString("authorized")
			})
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set(fiber.HeaderAuthorization, test.header)
			response, err := app.Test(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status || string(body) != test.body {
				t.Fatalf("status=%d body=%q", response.StatusCode, body)
			}
		})
	}
}

func TestBearerAuthKeepsInstancesSeparateUnderConcurrentRequests(t *testing.T) {
	apps := make([]*fiber.App, 2)
	tokens := []string{"fixture-alpha", "fixture-bravo"}
	for index, token := range tokens {
		app := fiber.New()
		app.Use(BearerAuthMiddleware(token))
		app.Get("/", func(c fiber.Ctx) error {
			if APIToken(c) != token {
				return c.SendStatus(http.StatusInternalServerError)
			}
			return c.SendStatus(http.StatusNoContent)
		})
		apps[index] = app
	}
	for caller := range 32 {
		t.Run(fmt.Sprint(caller), func(t *testing.T) {
			t.Parallel()
			index := caller % len(apps)
			for tokenIndex, token := range tokens {
				request := httptest.NewRequest(http.MethodGet, "/", nil)
				request.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
				response, err := apps[index].Test(request)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				want := http.StatusUnauthorized
				if tokenIndex == index {
					want = http.StatusNoContent
				}
				if response.StatusCode != want {
					t.Fatalf("instance=%d token index=%d status=%d want=%d", index, tokenIndex, response.StatusCode, want)
				}
			}
		})
	}
}
