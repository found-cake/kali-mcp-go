package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
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
