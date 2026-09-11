package tools

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestNiktoLowRateProfileUsesCallerSelectedPluginsWithBoundedDefaults(t *testing.T) {
	// Given: a low-rate Nikto request with caller-selected installed plugins.
	request := dto.NiktoRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
		Target:      "https://example.com", Timeout: 60,
		Plugins: []string{"headers", "content_search"},
	}

	// When: the safe command arguments are generated.
	args, err := NiktoArgs(request)
	if err != nil {
		t.Fatalf("build low-rate Nikto args: %v", err)
	}

	// Then: load controls are enforced while the caller's exact plugin selection is preserved.
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-Pause 0.2", "-maxtime 55s", "-Plugins headers;content_search"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("Nikto arguments missing %q from %v", expected, args)
		}
	}
}

func TestNiktoLowRateProfileRejectsMissingPluginsFasterPauseAndStateChange(t *testing.T) {
	// Given: low-rate requests without an explicit selection or with unsafe controls.
	requests := []dto.NiktoRequest{
		{ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate}, Target: "https://example.com"},
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

func TestNiktoExplicitCustomAllowsStateChangingPlugin(t *testing.T) {
	request := dto.NiktoRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileExplicitCustom},
		Target:      "https://example.com",
		Plugins:     []string{"put_del_test"},
	}

	args, err := NiktoArgs(request)
	if err != nil {
		t.Fatalf("build explicit-custom Nikto args: %v", err)
	}
	if !strings.Contains(strings.Join(args, " "), "-Plugins put_del_test") {
		t.Fatalf("explicit plugin selection missing from %v", args)
	}
}

func TestNiktoSafeProfileKeepsInternalDeadlineInsideOuterTimeout(t *testing.T) {
	// Given: a low-rate Nikto request whose internal deadline consumes the full outer timeout.
	request := dto.NiktoRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
		Target:      "https://example.com",
		MaxTime:     "60s",
		Timeout:     60,
		Plugins:     []string{"headers"},
	}

	// When: the safe execution arguments are validated.
	_, err := NiktoArgs(request)

	// Then: the request is rejected so Nikto can return partial output before the outer process deadline.
	if err == nil || !strings.Contains(err.Error(), "at most 55s") {
		t.Fatalf("error = %v, want bounded max_time guidance", err)
	}
}
