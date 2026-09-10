package tools

import (
	"fmt"

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
	case dto.JohnRequest:
		secrets = append(secrets, value.RedactValues...)
	}
	return normalizedSecrets(secrets)
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
