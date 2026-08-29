package tools

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestRedactRequestSecretsMasksKnownAndCallerSuppliedValues(t *testing.T) {
	// Given: a scan request containing an authorization value and an explicit secret.
	request := dto.SQLMapRequest{
		ScanOptions: dto.ScanOptions{RedactValues: []string{"customer-number-42"}},
		Headers:     map[string]string{"Authorization": "Bearer private-token"},
		Cookie:      "session=private-cookie",
	}
	output := "Bearer private-token session=private-cookie customer-number-42 remains"

	// When: request-scoped secrets are removed from tool output.
	redacted := RedactText(output, RequestSecrets(request))

	// Then: none of the supplied secret values remain observable.
	for _, secret := range []string{"private-token", "private-cookie", "customer-number-42"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q remains in %q", secret, redacted)
		}
	}
}
