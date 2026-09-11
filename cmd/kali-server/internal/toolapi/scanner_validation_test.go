package toolapi

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestValidateNmapRequestRejectsURLTarget(t *testing.T) {
	t.Parallel()

	err := validateNmapRequest(dto.NmapRequest{Target: "http://192.0.2.1/"})

	if err == nil || !strings.Contains(err.Error(), "IP address or hostname") {
		t.Fatalf("Nmap URL target was accepted: %v", err)
	}
}

func TestValidateNativeScannerControlRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		validate func() error
		field    string
	}{
		{name: "Nikto request timeout", validate: func() error {
			return validateNiktoRequest(dto.NiktoRequest{Target: "https://example.test", Plugins: []string{"headers"}, RequestTimeout: 301})
		}, field: "request_timeout"},
		{name: "Nikto failure limit", validate: func() error {
			return validateNiktoRequest(dto.NiktoRequest{Target: "https://example.test", Plugins: []string{"headers"}, FailureLimit: -1})
		}, field: "failure_limit"},
		{name: "Nuclei host errors", validate: func() error {
			return validateNucleiRequest(dto.NucleiRequest{Target: "https://example.test", MaxHostErrors: 1001})
		}, field: "max_host_errors"},
		{name: "Nuclei retries", validate: func() error {
			return validateNucleiRequest(dto.NucleiRequest{Target: "https://example.test", Retries: 11})
		}, field: "retries"},
		{name: "Dalfox scan timeout", validate: func() error {
			return validateDalfoxRequest(dto.DalfoxRequest{Target: "https://example.test/?q=FUZZ", ScanTimeout: 3601})
		}, field: "scan_timeout"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.validate()
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("invalid %s was accepted: %v", test.field, err)
			}
		})
	}
}

func TestValidateDalfoxAuthentication(t *testing.T) {
	t.Parallel()

	tests := []dto.DalfoxRequest{
		{Target: "https://example.test/?q=FUZZ", Headers: map[string]string{"Host": "foreign.test"}},
		{Target: "https://example.test/?q=FUZZ", Cookies: "session=value\r\nX-Injected: value"},
	}
	for _, request := range tests {
		if err := validateDalfoxRequest(request); err == nil {
			t.Fatalf("invalid Dalfox authentication was accepted: %+v", request)
		}
	}
}
