package tools

import (
	"reflect"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTsharkArgsUsesReadFileOverInterface(t *testing.T) {
	t.Parallel()

	args := TsharkArgs(dto.TsharkRequest{
		Interface: "eth0",
		ReadFile:  "/tmp/capture.pcap",
	})

	want := []string{"tshark", "-r", "/tmp/capture.pcap"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}

func TestTsharkArgsBuildsFiltersAndFields(t *testing.T) {
	t.Parallel()

	args := TsharkArgs(dto.TsharkRequest{
		Interface:     "eth0",
		CaptureFilter: "tcp port 80",
		DisplayFilter: "http",
		PacketCount:   "25",
		Duration:      "10",
		OutputFields:  "ip.src, ip.dst, tcp.port",
	})

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

	args := TsharkArgs(dto.TsharkRequest{
		ReadFile:       "/tmp/capture.pcap",
		AdditionalArgs: "-q -n",
	})

	want := []string{"tshark", "-r", "/tmp/capture.pcap", "-q", "-n"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args mismatch\nwant: %v\n got: %v", want, args)
	}
}
