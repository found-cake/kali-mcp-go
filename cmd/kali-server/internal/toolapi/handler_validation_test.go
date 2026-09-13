package toolapi

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestToolHandlerValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		handler fiber.Handler
		body    string
		message string
	}{
		{name: "nmap missing target", path: "/nmap/stream", handler: handleNmapStream, body: `{}`, message: "target is required"},
		{name: "command missing command", path: "/command/stream", handler: handleCommandStream, body: `{}`, message: "command is required"},
		{name: "nikto missing target", path: "/nikto/stream", handler: handleNiktoStream, body: `{}`, message: "target is required"},
		{name: "dirb missing URL", path: "/dirb/stream", handler: handleDirbStream, body: `{}`, message: "url is required"},
		{name: "wpscan missing URL", path: "/wpscan/stream", handler: handleWPScanStream, body: `{}`, message: "url is required"},
		{name: "enum4linux missing target", path: "/enum4linux/stream", handler: handleEnum4linuxStream, body: `{}`, message: "target is required"},
		{name: "sqlmap missing source", path: "/sqlmap/stream", handler: handleSQLMapStream, body: `{}`, message: "provide exactly one of url, request_file, or raw_request"},
		{name: "nmap malformed JSON", path: "/nmap/stream", handler: handleNmapStream, body: `{"target":`, message: "invalid request body"},
		{name: "tshark malformed JSON", path: "/tshark/stream", handler: handleTsharkStream, body: `{"read_file":`, message: "invalid request body"},
		{name: "tshark missing source", path: "/tshark/stream", handler: handleTsharkStream, body: `{"packet_count":"1"}`, message: "read_file or interface is required"},
		{name: "tshark conflicting sources", path: "/tshark/stream", handler: handleTsharkStream, body: `{"read_file":"/tmp/a.pcap","interface":"eth0"}`, message: "read_file and interface cannot be used together"},
		{name: "tshark invalid packet count", path: "/tshark/stream", handler: handleTsharkStream, body: `{"read_file":"/tmp/a.pcap","packet_count":"0"}`, message: "packet_count must be a positive integer"},
		{name: "metasploit multiline option", path: "/metasploit", handler: handleMetasploit, body: `{"module":"exploit/multi/handler","options":{"RHOSTS":"10.0.0.1\nsetg AutoRunScript post/multi/manage/shell_to_meterpreter"}}`, message: "unsupported resource-script characters"},
		{name: "metasploit command separator", path: "/metasploit", handler: handleMetasploit, body: `{"module":"exploit/multi/handler","target":"192.0.2.10","options":{"RPORT":"3000; set RHOSTS 198.51.100.20"}}`, message: "unsupported resource-script characters"},
		{name: "hydra username conflict", path: "/hydra", handler: handleHydra, body: `{"target":"127.0.0.1","service":"ssh","username":"root","username_file":"/tmp/users.txt","password":"toor"}`, message: "username and username_file cannot be used together"},
		{name: "hydra password conflict", path: "/hydra", handler: handleHydra, body: `{"target":"127.0.0.1","service":"ssh","username":"root","password":"toor","password_file":"/tmp/passwords.txt"}`, message: "password and password_file cannot be used together"},
		{name: "hydra stream missing target", path: "/hydra/stream", handler: handleHydraStream, body: `{"service":"ssh","username":"root","password":"toor"}`, message: "target and service are required"},
		{name: "hydra stream missing service", path: "/hydra/stream", handler: handleHydraStream, body: `{"target":"127.0.0.1","username":"root","password":"toor"}`, message: "target and service are required"},
		{name: "hydra stream username conflict", path: "/hydra/stream", handler: handleHydraStream, body: `{"target":"127.0.0.1","service":"ssh","username":"root","username_file":"/tmp/users.txt","password":"toor"}`, message: "username and username_file cannot be used together"},
		{name: "hydra stream password conflict", path: "/hydra/stream", handler: handleHydraStream, body: `{"target":"127.0.0.1","service":"ssh","username":"root","password":"toor","password_file":"/tmp/passwords.txt"}`, message: "password and password_file cannot be used together"},
		{name: "nmap malformed additional arguments", path: "/nmap/stream", handler: handleNmapStream, body: `{"target":"127.0.0.1","additional_args":"--script \"bad"}`, message: "invalid additional_args"},
		{name: "browser excessive wait", path: "/browser/stream", handler: handleBrowserStream, body: `{"url":"https://example.com","wait_milliseconds":30001}`, message: "wait_milliseconds must be between 0 and 30000"},
		{name: "JWT missing template", path: "/jwt/stream", handler: handleJWTStream, body: `{"token":"a.b.c","target_url":"https://example.com/me"}`, message: "exactly one of request_header or request_cookie is required"},
		{name: "JWT conflicting templates", path: "/jwt/stream", handler: handleJWTStream, body: `{"token":"a.b.c","target_url":"https://example.com/me","request_header":"Authorization: Bearer JWT_HERE","request_cookie":"token=JWT_HERE"}`, message: "exactly one of request_header or request_cookie is required"},
		{name: "JWT placeholder missing", path: "/jwt/stream", handler: handleJWTStream, body: `{"token":"a.b.c","target_url":"https://example.com/me","request_header":"Authorization: Bearer literal"}`, message: "template must contain JWT_HERE exactly once"},
		{name: "JWT duplicate placeholder", path: "/jwt/stream", handler: handleJWTStream, body: `{"token":"a.b.c","target_url":"https://example.com/me","request_cookie":"first=JWT_HERE; second=JWT_HERE"}`, message: "template must contain JWT_HERE exactly once"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Given: one malformed or incomplete tool request.
			app := fiber.New()
			app.Post(test.path, test.handler)
			request, err := http.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

			// When: the request reaches its public handler.
			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("app test: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			// Then: validation rejects it with the expected reason.
			if response.StatusCode != fiber.StatusBadRequest || !strings.Contains(string(body), test.message) {
				t.Fatalf("expected 400 containing %q, got status=%d body=%s", test.message, response.StatusCode, body)
			}
		})
	}
}

func TestValidateFFUFRequestRejectsInvalidHTTPControls(t *testing.T) {
	t.Parallel()

	// Given: FFUF requests with invalid per-request timeout or status filtering.
	tests := []struct {
		name    string
		request dto.FFUFRequest
		message string
	}{
		{name: "request timeout", request: dto.FFUFRequest{URL: "https://example.com/FUZZ", RequestTimeout: 301}, message: "request_timeout must be between 1 and 300"},
		{name: "status range", request: dto.FFUFRequest{URL: "https://example.com/FUZZ", FilterStatuses: "500-700"}, message: "filter_status_codes must contain HTTP codes between 100 and 599"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// When: the public request validator checks the controls.
			err := validateFFUFRequest(test.request)

			// Then: invalid values are rejected before FFUF starts.
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected %q, got %v", test.message, err)
			}
		})
	}
}
