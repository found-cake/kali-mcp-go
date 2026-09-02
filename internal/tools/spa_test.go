package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestMeasureSPABaselineFiltersStableFallbackBySize(t *testing.T) {
	// Given: every unknown route returns the same SPA shell.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<html><main>single page shell</main></html>"))
	}))
	defer server.Close()

	// When: multiple random missing routes are sampled.
	baseline, err := MeasureSPABaseline(context.Background(), server.URL+"/FUZZ")
	if err != nil {
		t.Fatalf("measure baseline: %v", err)
	}
	args, err := ApplyFFUFBaseline([]string{"ffuf", "-u", server.URL + "/FUZZ"}, baseline)
	if err != nil {
		t.Fatalf("apply baseline: %v", err)
	}

	// Then: the stable fallback is excluded by its observed response size.
	want := []string{"ffuf", "-u", server.URL + "/FUZZ", "-fs", strconv.Itoa(baseline.ContentLength)}
	if !baseline.Stable || !reflect.DeepEqual(args, want) {
		t.Fatalf("unexpected baseline or args: baseline=%+v args=%v", baseline, args)
	}
}

func TestMeasureSPABaseline_accepts_directory_base_url(t *testing.T) {
	// Given: a directory target whose unknown routes return one stable SPA shell.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<html><main>stable shell</main></html>"))
	}))
	defer server.Close()

	// When: the baseline is measured from the directory base URL.
	baseline, err := MeasureSPABaseline(context.Background(), server.URL+"/")

	// Then: the generated missing routes produce a usable stable baseline.
	if err != nil || !baseline.Stable || baseline.ContentLength == 0 {
		t.Fatalf("directory baseline was not measured: baseline=%+v err=%v", baseline, err)
	}
}

func TestApplyGobusterBaseline_excludes_stable_fallback_size(t *testing.T) {
	// Given: Gobuster arguments and a stable SPA response length.
	args := []string{"gobuster", "dir", "-u", "https://example.com", "-w", "/tmp/words.txt"}
	baseline := dto.SPABaseline{Stable: true, ContentLength: 9393}

	// When: the SPA baseline is applied.
	got, err := ApplyGobusterBaseline(args, baseline)

	// Then: Gobuster receives its native response-length exclusion flag.
	want := append(args, "--exclude-length", "9393")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected Gobuster baseline args: got=%v err=%v", got, err)
	}
}

func TestApplyFeroxbusterBaseline_excludes_stable_fallback_size(t *testing.T) {
	// Given: Feroxbuster arguments and a stable SPA response length.
	args := []string{"feroxbuster", "--url", "https://example.com", "--wordlist", "/tmp/words.txt"}
	baseline := dto.SPABaseline{Stable: true, ContentLength: 9393}

	// When: the SPA baseline is applied.
	got, err := ApplyFeroxbusterBaseline(args, baseline)

	// Then: Feroxbuster receives its native response-length exclusion flag.
	want := append(args, "--filter-size", "9393")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected Feroxbuster baseline args: got=%v err=%v", got, err)
	}
}
