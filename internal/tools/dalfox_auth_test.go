package tools

import (
	"reflect"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestDalfoxArgsUsesTypedAuthentication(t *testing.T) {
	t.Parallel()

	// Given: per-call headers and cookies owned by the caller.
	request := dto.DalfoxRequest{
		Target: "https://example.test/?q=FUZZ",
		Headers: map[string]string{
			"X-Tenant":      "customer-1",
			"Authorization": "Bearer test-token",
		},
		Cookies: "session=test-session",
	}

	// When: Dalfox arguments are generated.
	args, err := DalfoxArgs(request)

	// Then: authentication is passed directly in stable header order without persistent session state.
	want := []string{
		"dalfox", "scan", "https://example.test/?q=FUZZ", "--format", "json", "--no-color",
		"--headers", "Authorization: Bearer test-token", "--headers", "X-Tenant: customer-1", "--cookies", "session=test-session",
	}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Fatalf("Dalfox args mismatch\nwant: %v\n got: %v\n err: %v", want, args, err)
	}
}

func TestDalfoxArgsRejectsAuthenticationOverrides(t *testing.T) {
	t.Parallel()

	// Given: authentication supplied through untyped extra arguments.
	for _, extra := range []string{"-H 'Authorization: Bearer token'", "--headers='X-Test: value'", "--cookies=session=value"} {
		t.Run(extra, func(t *testing.T) {
			// When: Dalfox arguments are generated.
			_, err := DalfoxArgs(dto.DalfoxRequest{Target: "https://example.test/?q=FUZZ", AdditionalArgs: extra})

			// Then: the caller is directed to the typed authentication fields.
			if err == nil || !strings.Contains(err.Error(), "typed") {
				t.Fatalf("untyped authentication override was accepted: %v", err)
			}
		})
	}
}
