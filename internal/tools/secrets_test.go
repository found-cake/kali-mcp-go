package tools

import (
	"slices"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestRequestSecretsOnlyUsesCallerSuppliedValues(t *testing.T) {
	// Given: a scan request containing credentials and one explicitly selected redaction value.
	request := dto.SQLMapRequest{
		ScanOptions: dto.ScanOptions{RedactValues: []string{"customer-number-42"}},
		Headers:     map[string]string{"Authorization": "Bearer private-token"},
		Cookie:      "session=private-cookie",
	}
	output := "Bearer private-token session=private-cookie customer-number-42 remains"

	// When: request-scoped redaction values are collected and applied.
	secrets := RequestSecrets(request)
	redacted := RedactText(output, secrets)

	// Then: only the caller-selected value is removed; credentials remain raw evidence.
	if !slices.Equal(secrets, []string{"customer-number-42"}) {
		t.Fatalf("unexpected redaction values: %q", secrets)
	}
	if strings.Contains(redacted, "customer-number-42") || !strings.Contains(redacted, "private-token") || !strings.Contains(redacted, "private-cookie") {
		t.Fatalf("unexpected redacted output: %q", redacted)
	}
}

func TestHTTPRequestSecretsIgnoreCredentialLikeValuesByDefault(t *testing.T) {
	// Given: a request URL carrying one sensitive and one ordinary query value.
	request := dto.HTTPRequest{URL: "https://example.com/check?token=private-token&name=alice"}

	// When: request-scoped redaction values are collected.
	secrets := RequestSecrets(request)

	// Then: no value is inferred from names or URL structure.
	if len(secrets) != 0 {
		t.Fatalf("unexpected inferred HTTP request secrets: %q", secrets)
	}
}
