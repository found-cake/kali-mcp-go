package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTargetedToolArgumentsRejectAlternateSources(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	t.Setenv(defaultDirWordlistEnv, wordlist)

	tests := []struct {
		name  string
		build func() error
	}{
		{name: "nmap scan type positional target", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{Target: "192.0.2.10", ScanType: "-sT 198.51.100.20"})
			return err
		}},
		{name: "nmap input list", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{Target: "192.0.2.10", AdditionalArgs: "-iL=targets.txt"})
			return err
		}},
		{name: "ffuf URL", build: func() error {
			_, err := FFUFArgs(dto.FFUFRequest{URL: "https://example.test/FUZZ", AdditionalArgs: "-u=https://foreign.test/FUZZ"})
			return err
		}},
		{name: "ferox URL", build: func() error {
			_, err := FeroxbusterArgs(dto.FeroxbusterRequest{URL: "https://example.test/", AdditionalArgs: "--url=https://foreign.test/"})
			return err
		}},
		{name: "gobuster URL", build: func() error {
			_, err := GobusterArgs(dto.GobusterRequest{URL: "https://example.test/", AdditionalArgs: "--url=https://foreign.test/"})
			return err
		}},
		{name: "nikto host", build: func() error {
			_, err := NiktoArgs(dto.NiktoRequest{Target: "https://example.test/", AdditionalArgs: "-h=https://foreign.test/"})
			return err
		}},
		{name: "wpscan URL", build: func() error {
			_, err := WPScanArgs(dto.WPScanRequest{URL: "https://example.test/", AdditionalArgs: "--url=https://foreign.test/"})
			return err
		}},
		{name: "sqlmap request file", build: func() error {
			plan, err := PrepareSQLMap(dto.SQLMapRequest{URL: "https://example.test/?id=1", AdditionalArgs: "--request-file=foreign.txt"})
			if plan != nil {
				plan.Cleanup()
			}
			return err
		}},
		{name: "nuclei target", build: func() error {
			_, err := NucleiArgs(dto.NucleiRequest{Target: "https://example.test/", AllowUnsafe: true, AdditionalArgs: "-u=https://foreign.test/"})
			return err
		}},
		{name: "whatweb positional target", build: func() error {
			_, err := WhatWebArgs(dto.WhatWebRequest{Target: "https://example.test/", AdditionalArgs: "https://foreign.test/"})
			return err
		}},
		{name: "JWT live target", build: func() error {
			_, err := JWTToolArgs(dto.JWTRequest{Token: "a.b.c", TargetURL: "https://example.test/", AdditionalArgs: "-t=https://foreign.test/"})
			return err
		}},
		{name: "Dalfox request file", build: func() error {
			_, err := DalfoxArgs(dto.DalfoxRequest{Target: "https://example.test/?q=FUZZ", AdditionalArgs: "--file=foreign.txt"})
			return err
		}},
		{name: "Retire path", build: func() error {
			_, err := RetireArgs(dto.RetireRequest{Path: "/tmp/selected", AdditionalArgs: "--path=/tmp/foreign"})
			return err
		}},
		{name: "Hydra target list", build: func() error {
			_, err := HydraArgs(dto.HydraRequest{Target: "192.0.2.10", Service: "ssh", Username: "root", Password: "test", AdditionalArgs: "-M=targets.txt"})
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.build(); err == nil {
				t.Fatal("alternate target source was accepted")
			}
		})
	}
}
