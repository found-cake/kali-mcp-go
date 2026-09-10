package tools

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
)

type Redactor struct {
	secrets []string
}

func NewRedactor(secrets []string) Redactor {
	return Redactor{secrets: normalizedSecrets(secrets)}
}

func (r Redactor) Text(value string) string {
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func (r Redactor) Headers(headers http.Header) http.Header {
	redacted := headers.Clone()
	for _, values := range redacted {
		for index := range values {
			values[index] = r.Text(values[index])
		}
	}
	return redacted
}

func RedactHeaders(headers http.Header, secrets []string) http.Header {
	return NewRedactor(secrets).Headers(headers)
}

func RedactURL(value string, secrets []string) string {
	return RedactText(value, secrets)
}

func RedactText(value string, secrets []string) string {
	return NewRedactor(secrets).Text(value)
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
