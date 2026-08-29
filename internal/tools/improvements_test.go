package tools

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestNmapArgsPreservesLoopbackTarget(t *testing.T) {
	args, err := NmapArgs(dto.NmapRequest{Target: "127.0.0.1", ScanType: "-sT", AdditionalArgs: "-Pn"})
	if err != nil {
		t.Fatalf("build nmap args: %v", err)
	}
	want := []string{"nmap", "-sT", "-Pn", "127.0.0.1"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestSQLMapPlanSupportsRawJSONRequestAndCountsTraffic(t *testing.T) {
	plan, err := PrepareSQLMap(dto.SQLMapRequest{
		RawRequest:     "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nContent-Type: application/json\r\n\r\n{\"name\":\"admin*\"}",
		Headers:        map[string]string{"Authorization": "Bearer secret"},
		IgnoreCodes:    "401,500",
		TestParameters: "name",
	})
	if err != nil {
		t.Fatalf("prepare sqlmap: %v", err)
	}
	defer plan.Cleanup()

	requestBytes, err := os.ReadFile(plan.requestFile)
	if err != nil {
		t.Fatalf("read generated request: %v", err)
	}
	if !strings.Contains(string(requestBytes), "Host: 127.0.0.1:3000") {
		t.Fatalf("expected original raw Host header, got %q", requestBytes)
	}
	args := strings.Join(plan.Args(), " ")
	for _, required := range []string{"--ignore-stdin", "-r " + plan.requestFile, "--header Authorization: Bearer secret", "--ignore-code 401,500", "-p name", "-t " + plan.trafficFile} {
		if !strings.Contains(args, required) {
			t.Fatalf("expected %q in args: %s", required, args)
		}
	}
	traffic := "HTTP request [#1]:\nGET / HTTP/1.1\n\nHTTP response [#1] (200 OK):\n\nHTTP request [#2]:\nPOST / HTTP/1.1\n"
	if err := os.WriteFile(plan.trafficFile, []byte(traffic), 0o600); err != nil {
		t.Fatalf("write traffic fixture: %v", err)
	}
	if got := plan.HTTPRequestCount(); got != 2 {
		t.Fatalf("expected 2 requests, got %d", got)
	}
}

func TestSQLMapPlanAcceptsExistingRequestFile(t *testing.T) {
	t.Parallel()

	requestFile := t.TempDir() + "/request.txt"
	if err := os.WriteFile(requestFile, []byte("GET /?id=* HTTP/1.1\r\nHost: example.com\r\n\r\n"), 0o600); err != nil {
		t.Fatalf("write request: %v", err)
	}
	plan, err := PrepareSQLMap(dto.SQLMapRequest{RequestFile: requestFile})
	if err != nil {
		t.Fatalf("prepare sqlmap: %v", err)
	}
	defer plan.Cleanup()
	if !strings.Contains(strings.Join(plan.Args(), " "), "-r "+requestFile) {
		t.Fatalf("expected request file in args: %v", plan.Args())
	}
}

func TestNiktoArgsAddsLoadControls(t *testing.T) {
	t.Parallel()

	args, err := NiktoArgs(dto.NiktoRequest{Target: "https://example.com", PauseSeconds: 0.5, MaxTime: "2m", Tuning: "123"})
	if err != nil {
		t.Fatalf("build nikto args: %v", err)
	}
	want := []string{"nikto", "-h", "https://example.com", "-nocheck", "-nointeractive", "-Pause", "0.5", "-maxtime", "2m", "-Tuning", "123"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestNucleiArgsExcludeUnsafeTemplatesByDefault(t *testing.T) {
	t.Parallel()

	args, err := NucleiArgs(dto.NucleiRequest{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("build nuclei args: %v", err)
	}
	want := []string{"nuclei", "-u", "https://example.com", "-etags", "dos,fuzz", "-no-interactsh"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestReviewedToolArgsUseStableNonInteractiveDefaults(t *testing.T) {
	t.Parallel()
	mustArgs := func(args []string, err error) []string {
		if err != nil {
			t.Fatalf("build args: %v", err)
		}
		return args
	}

	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "whatweb", got: mustArgs(WhatWebArgs(dto.WhatWebRequest{Target: "https://example.com"})), want: []string{"whatweb", "https://example.com"}},
		{name: "dalfox", got: mustArgs(DalfoxArgs(dto.DalfoxRequest{Target: "https://example.com/?q=FUZZ"})), want: []string{"dalfox", "scan", "https://example.com/?q=FUZZ", "--format", "json", "--no-color"}},
		{name: "browser", got: mustArgs(BrowserArgs(dto.BrowserRequest{URL: "https://example.com", WaitMilliseconds: 250})), want: []string{"browser-check", "--url", "https://example.com", "--wait-ms", "250"}},
		{name: "retire", got: mustArgs(RetireArgs(dto.RetireRequest{Path: "/tmp/app"})), want: []string{"retire", "--path", "/tmp/app", "--outputformat", "json", "--exitwith", "0"}},
		{name: "osv", got: mustArgs(OSVArgs(dto.OSVRequest{Path: "/tmp/app"})), want: []string{"osv-scanner", "scan", "source", "-r", "/tmp/app", "--format", "json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(test.got, test.want) {
				t.Fatalf("args mismatch\nwant: %v\n got: %v", test.want, test.got)
			}
		})
	}
}

func TestJWTToolArgsDefaultsToAllTestsForLiveTarget(t *testing.T) {
	t.Parallel()

	args, err := JWTToolArgs(dto.JWTRequest{
		Token:         "header.payload.signature",
		TargetURL:     "https://example.com/me",
		RequestHeader: "Authorization: Bearer JWT_HERE",
		Canary:        "admin",
	})
	if err != nil {
		t.Fatalf("build jwt_tool args: %v", err)
	}
	want := []string{"jwt_tool", "header.payload.signature", "-t", "https://example.com/me", "-rh", "Authorization: Bearer JWT_HERE", "-cv", "admin", "-M", "at"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestRedactJohnOutputMasksRecoveredPlaintext(t *testing.T) {
	t.Parallel()

	output := "secret123        (alice)     \n1g 0:00:00:00 DONE\n"
	masked := RedactJohnOutput(output)
	if strings.Contains(masked, "secret123") || !strings.Contains(masked, "******** (alice)") {
		t.Fatalf("plaintext was not masked: %q", masked)
	}
}
