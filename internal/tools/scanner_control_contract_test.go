package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestNativeScannerControlsAreGeneratedFromTypedInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  string
		build    func([]byte) ([]string, error)
		expected []string
	}{
		{
			name: "Nuclei request failure controls",
			payload: `{"target":"https://example.test","max_host_errors":5,"request_timeout":3,"retries":2}`,
			build: func(payload []byte) ([]string, error) {
				var request dto.NucleiRequest
				if err := json.Unmarshal(payload, &request); err != nil {
					return nil, err
				}
				return NucleiArgs(request)
			},
			expected: []string{"-mhe", "5", "-timeout", "3", "-retries", "2"},
		},
		{
			name: "Nikto request failure controls",
			payload: `{"target":"https://example.test","request_timeout":3,"failure_limit":5}`,
			build: func(payload []byte) ([]string, error) {
				var request dto.NiktoRequest
				if err := json.Unmarshal(payload, &request); err != nil {
					return nil, err
				}
				return NiktoArgs(request)
			},
			expected: []string{"-timeout", "3", "-Option", "FAILURES=5"},
		},
		{
			name: "Dalfox bounded request controls",
			payload: `{"target":"https://example.test/?q=FUZZ","request_timeout":3,"scan_timeout":30,"retries":1}`,
			build: func(payload []byte) ([]string, error) {
				var request dto.DalfoxRequest
				if err := json.Unmarshal(payload, &request); err != nil {
					return nil, err
				}
				return DalfoxArgs(request)
			},
			expected: []string{"--timeout", "3", "--scan-timeout", "30", "--retries", "1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := test.build([]byte(test.payload))
			if err != nil {
				t.Fatalf("build scanner args: %v", err)
			}
			for index := 0; index < len(test.expected); index += 2 {
				if !containsFlagValue(args, test.expected[index], test.expected[index+1]) {
					t.Fatalf("args missing %s %s: %v", test.expected[index], test.expected[index+1], args)
				}
			}
		})
	}
}

func TestSafeDiscoveryScannersUseNativeFailureStops(t *testing.T) {
	t.Parallel()
	wordlist := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	ffuf, err := FFUFArgs(dto.FFUFRequest{ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon}, URL: "https://example.test/FUZZ", Wordlist: wordlist})
	if err != nil {
		t.Fatalf("build FFUF args: %v", err)
	}
	if !slices.Contains(ffuf, "-se") {
		t.Fatalf("FFUF spurious-error stop is missing: %v", ffuf)
	}

	ferox, err := FeroxbusterArgs(dto.FeroxbusterRequest{ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate}, URL: "https://example.test/", Wordlist: wordlist})
	if err != nil {
		t.Fatalf("build Feroxbuster args: %v", err)
	}
	if !slices.Contains(ferox, "--auto-bail") || !containsFlagValue(ferox, "--scan-limit", "1") {
		t.Fatalf("Feroxbuster global scan bound is missing: %v", ferox)
	}
}

func TestFFUFFiveXXThresholdIsNotAdvertisedAsHardControl(t *testing.T) {
	t.Parallel()

	_, err := EffectiveScanOptions("ffuf", dto.ScanOptions{Max5xxResponses: 2})
	if err == nil || !strings.Contains(err.Error(), "max_5xx_responses is not supported") {
		t.Fatalf("FFUF accepted an output-dependent 5xx threshold: %v", err)
	}

	capability, found := ToolCapability("ffuf_scan")
	if !found {
		t.Fatal("FFUF capability is missing")
	}
	for _, control := range capability.Controls {
		if control.Control == dto.ScanControlMax5xx {
			t.Fatalf("FFUF still advertises output-observed 5xx enforcement: %+v", capability)
		}
	}
}

func TestDalfoxSupportsNativeGlobalRateLimit(t *testing.T) {
	t.Parallel()

	args, err := ApplyScanControls(
		[]string{"dalfox", "scan", "https://example.test/?q=FUZZ"},
		dto.ScanOptions{RateLimit: 2, Concurrency: 1},
	)
	if err != nil {
		t.Fatalf("apply Dalfox controls: %v", err)
	}
	if !containsFlagValue(args, "--rate-limit", "2") || !containsFlagValue(args, "--workers", "1") {
		t.Fatalf("Dalfox rate or worker control missing: %v", args)
	}

	capability, found := ToolCapability("dalfox_scan")
	if !found {
		t.Fatal("Dalfox capability is missing")
	}
	if !supportsCapabilityControl(capability, dto.ScanControlRateLimit) {
		t.Fatalf("Dalfox rate limit is absent from capabilities: %+v", capability)
	}
}

func containsFlagValue(args []string, flag, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == flag && args[index+1] == value {
			return true
		}
	}
	return false
}
