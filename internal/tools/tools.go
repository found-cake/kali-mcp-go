// Package tools defines request types and argument builders for each Kali tool.
// Each builder is a pure function: (request) → []string args for executor.Run/Stream.
package tools

import (
	"fmt"
	"strings"
)

// splitArgs splits a space-separated string into a slice, ignoring empty strings.
func splitArgs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// ─── Request types ────────────────────────────────────────────────────────────

type CommandRequest struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"` // seconds; 0 → default
}

type NmapRequest struct {
	Target         string `json:"target"`
	ScanType       string `json:"scan_type"`       // default: -sCV
	Ports          string `json:"ports"`           // e.g. "80,443,8000-8080"
	AdditionalArgs string `json:"additional_args"` // default: -T4 -Pn
}

type GobusterRequest struct {
	URL            string `json:"url"`
	Mode           string `json:"mode"`     // dir|dns|fuzz|vhost; default: dir
	Wordlist       string `json:"wordlist"` // default: dirb/common.txt
	AdditionalArgs string `json:"additional_args"`
}

type DirbRequest struct {
	URL            string `json:"url"`
	Wordlist       string `json:"wordlist"`
	AdditionalArgs string `json:"additional_args"`
}

type NiktoRequest struct {
	Target         string `json:"target"`
	AdditionalArgs string `json:"additional_args"`
}

type SQLMapRequest struct {
	URL            string `json:"url"`
	Data           string `json:"data"`
	AdditionalArgs string `json:"additional_args"`
}

type MetasploitRequest struct {
	Module  string            `json:"module"`
	Options map[string]string `json:"options"`
}

type HydraRequest struct {
	Target         string `json:"target"`
	Service        string `json:"service"`
	Username       string `json:"username"`
	UsernameFile   string `json:"username_file"`
	Password       string `json:"password"`
	PasswordFile   string `json:"password_file"`
	AdditionalArgs string `json:"additional_args"`
}

type JohnRequest struct {
	HashFile       string `json:"hash_file"`
	Wordlist       string `json:"wordlist"`
	Format         string `json:"format"`
	AdditionalArgs string `json:"additional_args"`
}

type WPScanRequest struct {
	URL            string `json:"url"`
	AdditionalArgs string `json:"additional_args"`
}

type Enum4linuxRequest struct {
	Target         string `json:"target"`
	AdditionalArgs string `json:"additional_args"` // default: -a
}

// ─── Arg builders ─────────────────────────────────────────────────────────────

func NmapArgs(r NmapRequest) []string {
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

func GobusterArgs(r GobusterRequest) []string {
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

func DirbArgs(r DirbRequest) []string {
	wordlist := r.Wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/dirb/common.txt"
	}
	args := []string{"dirb", r.URL, wordlist}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func NiktoArgs(r NiktoRequest) []string {
	args := []string{"nikto", "-h", r.Target}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func SQLMapArgs(r SQLMapRequest) []string {
	args := []string{"sqlmap", "-u", r.URL, "--batch"}
	if r.Data != "" {
		args = append(args, "--data", r.Data)
	}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

// MetasploitScript returns the RC script content for msfconsole.
func MetasploitScript(r MetasploitRequest) string {
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

func HydraArgs(r HydraRequest) []string {
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

func JohnArgs(r JohnRequest) []string {
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

func WPScanArgs(r WPScanRequest) []string {
	args := []string{"wpscan", "--url", r.URL}
	return append(args, splitArgs(r.AdditionalArgs)...)
}

func Enum4linuxArgs(r Enum4linuxRequest) []string {
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-a"
	}
	args := []string{"enum4linux"}
	args = append(args, splitArgs(extra)...)
	return append(args, r.Target)
}

// ValidGobusterMode checks whether the mode string is a valid gobuster mode.
func ValidGobusterMode(mode string) bool {
	switch mode {
	case "", "dir", "dns", "fuzz", "vhost":
		return true
	}
	return false
}
