package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSafetyProfilesRejectImpactEscalationArguments(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	t.Setenv(defaultDirWordlistEnv, wordlist)

	tests := []struct {
		name  string
		build func() error
	}{
		{name: "FFUF state changing method", build: func() error {
			_, err := FFUFArgs(dto.FFUFRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				URL:         "https://example.test/FUZZ", AdditionalArgs: "-X=DELETE",
			})
			return err
		}},
		{name: "FFUF command input", build: func() error {
			_, err := FFUFArgs(dto.FFUFRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
				URL:         "https://example.test/FUZZ", AdditionalArgs: "-input-cmd=id",
			})
			return err
		}},
		{name: "FFUF cross-origin redirect", build: func() error {
			_, err := FFUFArgs(dto.FFUFRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				URL:         "https://example.test/FUZZ", AdditionalArgs: "-r",
			})
			return err
		}},
		{name: "Ferox state changing method", build: func() error {
			_, err := FeroxbusterArgs(dto.FeroxbusterRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				URL:         "https://example.test/", AdditionalArgs: "--methods=DELETE",
			})
			return err
		}},
		{name: "Ferox cross-origin redirect", build: func() error {
			_, err := FeroxbusterArgs(dto.FeroxbusterRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				URL:         "https://example.test/", AdditionalArgs: "--redirects",
			})
			return err
		}},
		{name: "Gobuster state changing method", build: func() error {
			_, err := GobusterArgs(dto.GobusterRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
				URL:         "https://example.test/", AdditionalArgs: "--method=DELETE",
			})
			return err
		}},
		{name: "Gobuster cross-origin redirect", build: func() error {
			_, err := GobusterArgs(dto.GobusterRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
				URL:         "https://example.test/", AdditionalArgs: "--follow-redirect",
			})
			return err
		}},
		{name: "Nmap DoS scripts", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				Target:      "192.0.2.10", AdditionalArgs: "--script=dos",
			})
			return err
		}},
		{name: "Nmap script arguments", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				Target:      "192.0.2.10", AdditionalArgs: "--script-args=unsafe=value",
			})
			return err
		}},
		{name: "Nmap spoofed source", build: func() error {
			_, err := NmapArgs(dto.NmapRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				Target:      "192.0.2.10", AdditionalArgs: "-S=198.51.100.20",
			})
			return err
		}},
		{name: "Nuclei unsafe opt-out", build: func() error {
			_, err := NucleiArgs(dto.NucleiRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				Target:      "https://example.test/", AllowUnsafe: true, AdditionalArgs: "--include-tags=dos",
			})
			return err
		}},
		{name: "Nikto DoS tuning", build: func() error {
			_, err := NiktoArgs(dto.NiktoRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
				Target:      "https://example.test/", Tuning: "6",
			})
			return err
		}},
		{name: "Nikto redirects", build: func() error {
			_, err := NiktoArgs(dto.NiktoRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileWebDiscoveryLowRate},
				Target:      "https://example.test/", AdditionalArgs: "-followredirects",
			})
			return err
		}},
		{name: "SQLMap operating system shell", build: func() error {
			plan, err := PrepareSQLMap(dto.SQLMapRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSQLILowRisk},
				URL:         "https://example.test/?id=1", AdditionalArgs: "--os-shell",
			})
			if plan != nil {
				plan.Cleanup()
			}
			return err
		}},
		{name: "Dalfox state changing method", build: func() error {
			_, err := DalfoxArgs(dto.DalfoxRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileBrowserXSSConfirm},
				Target:      "https://example.test/?q=FUZZ", AdditionalArgs: "--method=POST",
			})
			return err
		}},
		{name: "Dalfox redirects", build: func() error {
			_, err := DalfoxArgs(dto.DalfoxRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileBrowserXSSConfirm},
				Target:      "https://example.test/?q=FUZZ", AdditionalArgs: "-F",
			})
			return err
		}},
		{name: "WhatWeb redirects", build: func() error {
			_, err := WhatWebArgs(dto.WhatWebRequest{
				ScanOptions: dto.ScanOptions{Profile: dto.ProfileSafeRecon},
				Target:      "https://example.test/", AdditionalArgs: "--follow-redirect=always",
			})
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.build(); err == nil {
				t.Fatal("safety profile accepted an impact-escalating option")
			}
		})
	}
}

func TestSQLMapLowRiskProfilePinsVerificationSettings(t *testing.T) {
	plan, err := PrepareSQLMap(dto.SQLMapRequest{
		ScanOptions: dto.ScanOptions{Profile: dto.ProfileSQLILowRisk},
		URL:         "https://example.test/?id=1",
	})
	if err != nil {
		t.Fatalf("prepare SQLMap: %v", err)
	}
	defer plan.Cleanup()
	args := plan.Args()
	for _, expected := range []string{"--risk=1", "--level=1", "--technique=BEU", "--ignore-redirects"} {
		if !containsArg(args, expected) {
			t.Fatalf("low-risk SQLMap args missing %q: %v", expected, args)
		}
	}
}
