package tools

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestNiktoLowRateProfileAppliesBoundedDefaults(t *testing.T) {
	// Given: a low-rate Nikto request without caller-supplied load controls.
	request := dto.NiktoRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
		Target:      "https://example.com", Timeout: 60,
	}

	// When: the safe command arguments are generated.
	args, err := NiktoArgs(request)
	if err != nil {
		t.Fatalf("build low-rate Nikto args: %v", err)
	}

	// Then: a native delay, an internal completion deadline, and the safe plugin allow-list are enforced.
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-Pause 0.2", "-maxtime 55s", "-Plugins " + safeNiktoPlugins} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("Nikto safe defaults missing %q from %v", expected, args)
		}
	}
}

func TestNiktoLowRateProfileRejectsFasterPauseAndUnsafePlugin(t *testing.T) {
	// Given: low-rate requests that weaken delay or escape the plugin allow-list.
	requests := []dto.NiktoRequest{
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate}, Target: "https://example.com", PauseSeconds: 0.1},
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate}, Target: "https://example.com", Plugins: []string{"put_del_test"}},
	}

	// When: each request is converted into command arguments.
	for _, request := range requests {
		_, err := NiktoArgs(request)

		// Then: neither profile relaxation reaches the Nikto process.
		if err == nil {
			t.Fatalf("unsafe low-rate request was accepted: %+v", request)
		}
	}
}

func TestNiktoSafeProfileKeepsInternalDeadlineInsideOuterTimeout(t *testing.T) {
	// Given: a low-rate Nikto request whose internal deadline consumes the full outer timeout.
	request := dto.NiktoRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
		Target:      "https://example.com",
		MaxTime:     "60s",
		Timeout:     60,
	}

	// When: the safe execution arguments are validated.
	_, err := NiktoArgs(request)

	// Then: the request is rejected so Nikto can return partial output before the outer process deadline.
	if err == nil || !strings.Contains(err.Error(), "at most 55s") {
		t.Fatalf("error = %v, want bounded max_time guidance", err)
	}
}
