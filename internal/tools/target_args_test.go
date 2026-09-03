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
		{name: "nmap resume file", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{Target: "192.0.2.10", AdditionalArgs: "--resume=scan.xml"})
			return err
		}},
		{name: "nmap idle scan zombie", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{Target: "192.0.2.10", ScanType: "-sI198.51.100.20"})
			return err
		}},
		{name: "nmap FTP relay", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{Target: "192.0.2.10", AdditionalArgs: "-b=ftp://198.51.100.20"})
			return err
		}},
		{name: "ffuf URL", build: func() error {
			_, err := FFUFArgs(dto.FFUFRequest{URL: "https://example.test/FUZZ", AdditionalArgs: "-u=https://foreign.test/FUZZ"})
			return err
		}},
		{name: "ferox URL", build: func() error {
			_, err := FeroxbusterArgs(dto.FeroxbusterRequest{URL: "https://example.test/", AdditionalArgs: "-u=https://foreign.test/"})
			return err
		}},
		{name: "gobuster URL", build: func() error {
			_, err := GobusterArgs(dto.GobusterRequest{URL: "https://example.test/", AdditionalArgs: "--url=https://foreign.test/"})
			return err
		}},
		{name: "nikto host", build: func() error {
			_, err := NiktoArgs(dto.NiktoRequest{Target: "https://example.test/", AdditionalArgs: "-url=https://foreign.test/"})
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
		{name: "sqlmap direct database", build: func() error {
			plan, err := PrepareSQLMap(dto.SQLMapRequest{URL: "https://example.test/?id=1", AdditionalArgs: "--direct=sqlite:///tmp/foreign.db"})
			if plan != nil {
				plan.Cleanup()
			}
			return err
		}},
		{name: "sqlmap secondary URL", build: func() error {
			plan, err := PrepareSQLMap(dto.SQLMapRequest{URL: "https://example.test/?id=1", AdditionalArgs: "--second-url=https://foreign.test/"})
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
		{name: "whatweb URL prefix", build: func() error {
			_, err := WhatWebArgs(dto.WhatWebRequest{Target: "example.test", AdditionalArgs: "--url-prefix=https://foreign.test/"})
			return err
		}},
		{name: "JWT live target", build: func() error {
			_, err := JWTToolArgs(dto.JWTRequest{Token: "a.b.c", TargetURL: "https://example.test/", AdditionalArgs: "--request=request.txt"})
			return err
		}},
		{name: "Dalfox request file", build: func() error {
			_, err := DalfoxArgs(dto.DalfoxRequest{Target: "https://example.test/?q=FUZZ", AdditionalArgs: "https://foreign.test/?q=FUZZ"})
			return err
		}},
		{name: "Retire path", build: func() error {
			_, err := RetireArgs(dto.RetireRequest{Path: "/tmp/selected", AdditionalArgs: "--jspath=/tmp/foreign"})
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

func TestTargetContextRejectsCLIHostOverrides(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	t.Setenv(defaultDirWordlistEnv, wordlist)
	context := "signed-context"

	tests := []struct {
		name  string
		build func() error
	}{
		{name: "Nuclei Host header", build: func() error {
			_, err := NucleiArgs(dto.NucleiRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "https://example.test/", AdditionalArgs: "-H 'Host: foreign.test'"})
			return err
		}},
		{name: "FFUF Host header", build: func() error {
			_, err := FFUFArgs(dto.FFUFRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, URL: "https://example.test/FUZZ", AdditionalArgs: "-H 'Host: foreign.test'"})
			return err
		}},
		{name: "Ferox Host header", build: func() error {
			_, err := FeroxbusterArgs(dto.FeroxbusterRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, URL: "https://example.test/", AdditionalArgs: "--headers='Host: foreign.test'"})
			return err
		}},
		{name: "Gobuster vhost mode", build: func() error {
			_, err := GobusterArgs(dto.GobusterRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, URL: "https://example.test/", Mode: "vhost"})
			return err
		}},
		{name: "Nikto vhost", build: func() error {
			_, err := NiktoArgs(dto.NiktoRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "https://example.test/", AdditionalArgs: "-vhost=foreign.test"})
			return err
		}},
		{name: "WhatWeb Host header", build: func() error {
			_, err := WhatWebArgs(dto.WhatWebRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "https://example.test/", AdditionalArgs: "--header='Host: foreign.test'"})
			return err
		}},
		{name: "Dalfox Host header", build: func() error {
			_, err := DalfoxArgs(dto.DalfoxRequest{ScanOptions: dto.ScanOptions{TargetContext: context}, Target: "https://example.test/?q=FUZZ", AdditionalArgs: "--header='Host: foreign.test'"})
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.build(); err == nil {
				t.Fatal("target_context accepted a virtual-host override")
			}
		})
	}
}

func TestHydraArgsUseTypedPortAndRejectAdditionalOverride(t *testing.T) {
	request := dto.HydraRequest{Target: "192.0.2.10", Port: 3000, Service: "http-get", Username: "user", Password: "pass"}
	args, err := HydraArgs(request)
	if err != nil {
		t.Fatalf("build Hydra args: %v", err)
	}
	if !containsArg(args, "-s") || !containsArg(args, "3000") {
		t.Fatalf("Hydra typed port missing: %v", args)
	}
	request.AdditionalArgs = "-s=22"
	if _, err := HydraArgs(request); err == nil {
		t.Fatal("Hydra accepted an additional port override")
	}
}
