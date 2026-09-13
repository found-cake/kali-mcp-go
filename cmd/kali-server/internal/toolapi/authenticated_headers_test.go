package toolapi

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestBrowserHeadersValidation(t *testing.T) {
	valid := dto.BrowserRequest{
		URL:     "https://example.test/app",
		Headers: map[string]string{"Authorization": "Bearer token", "Cookie": "session=alpha"},
	}
	if err := validateBrowserRequest(valid); err != nil {
		t.Fatalf("valid authenticated browser request rejected: %v", err)
	}

	invalid := valid
	invalid.Headers = map[string]string{"Host": "other.example"}
	if err := validateBrowserRequest(invalid); err == nil || !strings.Contains(err.Error(), "Host") {
		t.Fatalf("expected Host override rejection, got %v", err)
	}
}

func TestRetireHeadersValidation(t *testing.T) {
	valid := dto.RetireRequest{
		URL:     "https://example.test/app",
		Headers: map[string]string{"Authorization": "Bearer token", "Cookie": "session=alpha"},
	}
	if err := validateRetireRequest(valid); err != nil {
		t.Fatalf("valid authenticated Retire request rejected: %v", err)
	}

	pathRequest := dto.RetireRequest{Path: "/workspace/app.js", Headers: valid.Headers}
	if err := validateRetireRequest(pathRequest); err == nil || !strings.Contains(err.Error(), "downloads") {
		t.Fatalf("expected headers with path mode to be rejected, got %v", err)
	}

	invalid := valid
	invalid.Headers = map[string]string{"X-Test": "valid\r\ninjected: value"}
	if err := validateRetireRequest(invalid); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid header rejection, got %v", err)
	}
}
