package toolapi

import (
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const maximumAuthenticatedHeaders = 64

func validateAuthenticatedHeaders(headers map[string]string) error {
	if len(headers) > maximumAuthenticatedHeaders {
		return fmt.Errorf("headers cannot contain more than %d entries", maximumAuthenticatedHeaders)
	}
	for name, value := range headers {
		if strings.EqualFold(name, "Host") {
			return fmt.Errorf("Host header overrides are not permitted")
		}
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("headers contain an invalid name or value")
		}
	}
	return nil
}
