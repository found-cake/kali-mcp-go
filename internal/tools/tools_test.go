package tools

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTsharkArgsUsesReadFileOverInterface(t *testing.T) {
	t.Parallel()

	args, err := TsharkArgs(dto.TsharkRequest{
		Interface: "eth0",
		ReadFile:  "/tmp/capture.pcap",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	want := []string{"tshark", "-r", "/tmp/capture.pcap"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestTsharkArgsBuildsFiltersAndFields(t *testing.T) {
	t.Parallel()

	args, err := TsharkArgs(dto.TsharkRequest{
		Interface:     "eth0",
		CaptureFilter: "tcp port 80",
		DisplayFilter: "http",
		PacketCount:   "25",
		Duration:      "10",
		OutputFields:  "ip.src, ip.dst, tcp.port",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	want := []string{
		"tshark", "-i", "eth0", "-f", "tcp port 80", "-Y", "http", "-c", "25", "-a", "duration:10",
		"-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.port",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestTsharkArgsAppendsAdditionalArgs(t *testing.T) {
	t.Parallel()

	args, err := TsharkArgs(dto.TsharkRequest{
		ReadFile:       "/tmp/capture.pcap",
		AdditionalArgs: "-q -n",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	want := []string{"tshark", "-r", "/tmp/capture.pcap", "-q", "-n"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestSplitArgsParsesQuotedSegments(t *testing.T) {
	t.Parallel()

	args, err := splitArgs(`--script "http title" --user 'admin user' -q`)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := []string{"--script", "http title", "--user", "admin user", "-q"}

	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestSplitArgsParsesEscapedSpaces(t *testing.T) {
	t.Parallel()

	args, err := splitArgs(`--path /tmp/a\ b --name foo`)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := []string{"--path", "/tmp/a b", "--name", "foo"}

	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestSplitArgsRejectsUnterminatedQuote(t *testing.T) {
	t.Parallel()

	_, err := splitArgs(`--flag "unterminated`)
	if err == nil || !strings.Contains(err.Error(), "unterminated quote") {
		t.Fatalf("expected unterminated quote error, got %v", err)
	}
}

func TestNmapArgsRejectsMalformedAdditionalArgs(t *testing.T) {
	t.Parallel()

	_, err := NmapArgs(dto.NmapRequest{Target: "127.0.0.1", AdditionalArgs: `--script "bad`})
	if err == nil || !strings.Contains(err.Error(), "invalid additional_args") {
		t.Fatalf("expected additional_args parse error, got %v", err)
	}
}

func TestMetasploitScriptUsesRunForAuxiliaryAndExit(t *testing.T) {
	t.Parallel()

	script := MetasploitScript(dto.MetasploitRequest{Module: "auxiliary/scanner/http/title"})
	if !strings.Contains(script, "\nrun\nexit -y\n") {
		t.Fatalf("expected run + exit in script, got %q", script)
	}
}

func TestMetasploitScriptUsesExploitForExploitModules(t *testing.T) {
	t.Parallel()

	script := MetasploitScript(dto.MetasploitRequest{Module: "exploit/multi/handler"})
	if !strings.Contains(script, "\nexploit\nexit -y\n") {
		t.Fatalf("expected exploit + exit in script, got %q", script)
	}
}

func TestGobusterArgsUsesEnvWordlistOverride(t *testing.T) {
	wordlist, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	if err != nil {
		t.Fatalf("create temp wordlist: %v", err)
	}
	defer wordlist.Close()
	t.Setenv(defaultDirWordlistEnv, wordlist.Name())

	args, err := GobusterArgs(dto.GobusterRequest{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	want := []string{"gobuster", "dir", "-u", "https://example.com", "-w", wordlist.Name()}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}
