package tools

import (
	"fmt"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"strings"
)

func splitArgs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func NmapArgs(r dto.NmapRequest) []string {
	scanType := r.ScanType
	if scanType == "" {
		scanType = "-sCV"
	}
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-T4 -Pn"
	}

	args := append([]string{"nmap"}, splitArgs(scanType)...)
	if r.Ports != "" {
		args = append(args, "-p", r.Ports)
	}
	args = append(args, splitArgs(extra)...)
	args = append(args, r.Target)
	return args
}

func GobusterArgs(r dto.GobusterRequest) []string {
	mode := r.Mode
	if mode == "" {
		mode = "dir"
	}
	wordlist := r.Wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/dirb/common.txt"
	}

	args := []string{"gobuster", mode, "-u", r.URL, "-w", wordlist}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func DirbArgs(r dto.DirbRequest) []string {
	wordlist := r.Wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/dirb/common.txt"
	}
	args := []string{"dirb", r.URL, wordlist}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func NiktoArgs(r dto.NiktoRequest) []string {
	args := []string{"nikto", "-h", r.Target}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func TsharkArgs(r dto.TsharkRequest) []string {
	args := []string{"tshark"}

	if r.ReadFile != "" {
		args = append(args, "-r", r.ReadFile)
	} else if r.Interface != "" {
		args = append(args, "-i", r.Interface)
	}
	if r.CaptureFilter != "" {
		args = append(args, "-f", r.CaptureFilter)
	}
	if r.DisplayFilter != "" {
		args = append(args, "-Y", r.DisplayFilter)
	}
	if r.PacketCount != "" {
		args = append(args, "-c", r.PacketCount)
	}
	if r.Duration != "" {
		args = append(args, "-a", "duration:"+r.Duration)
	}
	if r.OutputFields != "" {
		args = append(args, "-T", "fields")
		for _, field := range strings.Split(r.OutputFields, ",") {
			trimmed := strings.TrimSpace(field)
			if trimmed != "" {
				args = append(args, "-e", trimmed)
			}
		}
	}

	return append(args, splitArgs(r.AdditionalArgs)...)
}

func SQLMapArgs(r dto.SQLMapRequest) []string {
	args := []string{"sqlmap", "-u", r.URL, "--batch"}
	if r.Data != "" {
		args = append(args, "--data", r.Data)
	}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func MetasploitScript(r dto.MetasploitRequest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "use %s\n", r.Module)
	for k, v := range r.Options {
		fmt.Fprintf(&sb, "set %s %s\n", k, v)
	}
	sb.WriteString("exploit\n")
	return sb.String()
}

func MetasploitArgs(rcFile string) []string {
	return []string{"msfconsole", "-q", "-r", rcFile}
}

func HydraArgs(r dto.HydraRequest) []string {
	args := []string{"hydra", "-t", "4"}
	if r.Username != "" {
		args = append(args, "-l", r.Username)
	} else {
		args = append(args, "-L", r.UsernameFile)
	}
	if r.Password != "" {
		args = append(args, "-p", r.Password)
	} else {
		args = append(args, "-P", r.PasswordFile)
	}
	args = append(args, r.Target, r.Service)
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func JohnArgs(r dto.JohnRequest) []string {
	wordlist := r.Wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/rockyou.txt"
	}
	args := []string{"john"}
	if r.Format != "" {
		args = append(args, "--format="+r.Format)
	}
	args = append(args, "--wordlist="+wordlist)
	args = append(args, splitArgs(r.AdditionalArgs)...)
	return append(args, r.HashFile)
}

func WPScanArgs(r dto.WPScanRequest) []string {
	args := []string{"wpscan", "--url", r.URL}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func Enum4linuxArgs(r dto.Enum4linuxRequest) []string {
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-a"
	}
	args := []string{"enum4linux"}
	args = append(args, splitArgs(extra)...)
	return append(args, r.Target)
}
func ValidGobusterMode(mode string) bool {
	switch mode {
	case "", "dir", "dns", "fuzz", "vhost":
		return true
	}
	return false
}
