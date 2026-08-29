package tools

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	maximumRedactionValues = 64
	maximumRedactionBytes  = 64 * 1024
)

func RequestSecrets(request any) []string {
	var secrets []string
	if scanRequest, ok := request.(dto.ScanRequest); ok {
		secrets = append(secrets, scanRequest.GetScanOptions().RedactValues...)
	}
	switch value := request.(type) {
	case dto.CommandRequest:
		secrets = append(secrets, value.RedactValues...)
	case dto.MetasploitRequest:
		secrets = append(secrets, value.RedactValues...)
		for name, option := range value.Options {
			if sensitiveName(name) {
				secrets = append(secrets, option)
			}
		}
	case dto.SQLMapRequest:
		secrets = append(secrets, value.Cookie)
		for name, header := range value.Headers {
			if sensitiveName(name) {
				secrets = append(secrets, header)
			}
		}
	case dto.HydraRequest:
		secrets = append(secrets, value.Password)
	case dto.JohnRequest:
		secrets = append(secrets, value.Hash)
		secrets = append(secrets, value.RedactValues...)
	case dto.JWTRequest:
		secrets = append(secrets, value.Token, value.RequestHeader, value.RequestCookie)
	case dto.HTTPRequest:
		for name, header := range value.Headers {
			if sensitiveName(name) {
				secrets = append(secrets, header)
			}
		}
	}
	return normalizedSecrets(secrets)
}

func RedactHeaders(headers http.Header, secrets []string) http.Header {
	redacted := headers.Clone()
	for name, values := range redacted {
		if sensitiveName(name) {
			redacted[name] = []string{"[REDACTED]"}
			continue
		}
		for index := range values {
			values[index] = RedactText(values[index], secrets)
		}
	}
	return redacted
}

func RedactText(value string, secrets []string) string {
	for _, secret := range normalizedSecrets(secrets) {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func ValidateRequestSecrets(request any) error {
	secrets := RequestSecrets(request)
	if len(secrets) > maximumRedactionValues {
		return fmt.Errorf("too many sensitive values to redact")
	}
	total := 0
	for _, secret := range secrets {
		total += len(secret)
	}
	if total > maximumRedactionBytes {
		return fmt.Errorf("sensitive values exceed redaction size limit")
	}
	return nil
}

func normalizedSecrets(values []string) []string {
	seen := make(map[string]bool, len(values))
	secrets := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		secrets = append(secrets, value)
	}
	slices.SortFunc(secrets, func(left, right string) int {
		return cmp.Compare(len(right), len(left))
	})
	return secrets
}

func sensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"authorization", "cookie", "password", "passwd", "secret", "token", "api-key", "apikey"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
