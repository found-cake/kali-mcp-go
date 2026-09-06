package toolapi

import (
	"fmt"
	"slices"
	"strings"

	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func validateSQLMapRequest(request dto.SQLMapRequest) error {
	sources := 0
	for _, source := range []string{request.URL, request.RequestFile, request.RawRequest} {
		if strings.TrimSpace(source) != "" {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("provide exactly one of url, request_file, or raw_request")
	}
	for name, value := range request.Headers {
		if strings.TrimSpace(name) == "" || containsLineBreak(name) || containsLineBreak(value) {
			return fmt.Errorf("headers must have non-empty names and no line breaks")
		}
	}
	if containsLineBreak(request.Cookie) || containsLineBreak(request.ContentType) {
		return fmt.Errorf("cookie and content_type must not contain line breaks")
	}
	abortCodes, err := tools.ParseSQLMapStatusCodes("abort_codes", request.AbortCodes)
	if err != nil {
		return err
	}
	ignoreCodes, ignoreAll, err := parseSQLMapIgnoreCodes(request.IgnoreCodes)
	if err != nil {
		return err
	}
	for _, code := range abortCodes {
		if ignoreAll || slices.Contains(ignoreCodes, code) {
			return fmt.Errorf("HTTP status %d cannot appear in both abort_codes and ignore_codes", code)
		}
	}
	return nil
}

func parseSQLMapIgnoreCodes(value string) ([]int, bool, error) {
	if strings.TrimSpace(value) == "*" {
		return nil, true, nil
	}
	codes, err := tools.ParseSQLMapStatusCodes("ignore_codes", value)
	if err != nil {
		return nil, false, err
	}
	return codes, false, nil
}
