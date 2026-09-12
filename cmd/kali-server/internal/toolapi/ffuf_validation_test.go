package toolapi

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestValidateFFUFRequestRejectsMissingFuzzKeywordBeforeExecution(t *testing.T) {
	t.Parallel()

	err := validateFFUFRequest(dto.FFUFRequest{URL: "https://example.test/"})
	if err == nil || !strings.Contains(err.Error(), "FUZZ") {
		t.Fatalf("validateFFUFRequest() error = %v, want a missing FUZZ error", err)
	}
}

func TestValidateFFUFRequestAcceptsFuzzKeywordOutsideURL(t *testing.T) {
	t.Parallel()

	err := validateFFUFRequest(dto.FFUFRequest{
		URL:            "https://example.test/",
		AdditionalArgs: `-H "X-Test: FUZZ"`,
	})
	if err != nil {
		t.Fatalf("validateFFUFRequest() error = %v, want nil", err)
	}
}
