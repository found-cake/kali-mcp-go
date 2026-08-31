package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

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
		{name: "metasploit multiline option", path: "/metasploit", handler: handleMetasploit, body: `{"module":"exploit/multi/handler","options":{"RHOSTS":"10.0.0.1\nsetg AutoRunScript post/multi/manage/shell_to_meterpreter"}}`, message: "options must not contain line breaks"},
		{name: "hydra username conflict", path: "/hydra", handler: handleHydra, body: `{"target":"127.0.0.1","service":"ssh","username":"root","username_file":"/tmp/users.txt","password":"toor"}`, message: "username and username_file cannot be used together"},
		{name: "hydra password conflict", path: "/hydra", handler: handleHydra, body: `{"target":"127.0.0.1","service":"ssh","username":"root","password":"toor","password_file":"/tmp/passwords.txt"}`, message: "password and password_file cannot be used together"},
		{name: "hydra stream missing target", path: "/hydra/stream", handler: handleHydraStream, body: `{"service":"ssh","username":"root","password":"toor"}`, message: "target and service are required"},
		{name: "hydra stream missing service", path: "/hydra/stream", handler: handleHydraStream, body: `{"target":"127.0.0.1","username":"root","password":"toor"}`, message: "target and service are required"},
		{name: "hydra stream username conflict", path: "/hydra/stream", handler: handleHydraStream, body: `{"target":"127.0.0.1","service":"ssh","username":"root","username_file":"/tmp/users.txt","password":"toor"}`, message: "username and username_file cannot be used together"},
		{name: "hydra stream password conflict", path: "/hydra/stream", handler: handleHydraStream, body: `{"target":"127.0.0.1","service":"ssh","username":"root","password":"toor","password_file":"/tmp/passwords.txt"}`, message: "password and password_file cannot be used together"},
		{name: "nmap malformed additional arguments", path: "/nmap/stream", handler: handleNmapStream, body: `{"target":"127.0.0.1","additional_args":"--script \"bad"}`, message: "invalid additional_args"},
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
