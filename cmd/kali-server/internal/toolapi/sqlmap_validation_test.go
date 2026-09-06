package toolapi

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestValidateSQLMapRequestAcceptsDistinctAbortAndIgnoreCodes(t *testing.T) {
	request := dto.SQLMapRequest{
		URL:         "https://example.test/?id=1",
		AbortCodes:  "500,503",
		IgnoreCodes: "401,404",
	}

	if err := validateSQLMapRequest(request); err != nil {
		t.Fatalf("valid SQLmap status controls rejected: %v", err)
	}
}

func TestValidateSQLMapRequestRejectsConflictingStatusCodes(t *testing.T) {
	request := dto.SQLMapRequest{
		URL:         "https://example.test/?id=1",
		AbortCodes:  "500,503",
		IgnoreCodes: "401,500",
	}

	err := validateSQLMapRequest(request)
	if err == nil || !strings.Contains(err.Error(), "both abort_codes and ignore_codes") {
		t.Fatalf("conflicting SQLmap status controls accepted: %v", err)
	}
}

func TestValidateSQLMapRequestRejectsInvalidAbortCode(t *testing.T) {
	request := dto.SQLMapRequest{URL: "https://example.test/?id=1", AbortCodes: "500,700"}

	err := validateSQLMapRequest(request)
	if err == nil || !strings.Contains(err.Error(), "between 100 and 599") {
		t.Fatalf("invalid SQLmap abort code accepted: %v", err)
	}
}
