package tools

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	defaultDirWordlistEnv  = "KALI_MCP_DIR_WORDLIST"
	defaultDirWordlist     = "/usr/share/wordlists/dirb/common.txt"
	defaultJohnWordlistEnv = "KALI_MCP_JOHN_WORDLIST"
	defaultJohnWordlist    = "/usr/share/wordlists/rockyou.txt"
)

func DefaultDirWordlistPath() string {
	return defaultWordlistPath(defaultDirWordlistEnv, defaultDirWordlist)
}

func DefaultJohnWordlistPath() string {
	return defaultWordlistPath(defaultJohnWordlistEnv, defaultJohnWordlist)
}

func WordlistExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func splitArgs(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	return shellSplit(s)
}

func appendSplitArgs(args []string, extra string, fieldName string) ([]string, error) {
	parts, err := splitArgs(extra)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", fieldName, err)
	}
	return append(args, parts...), nil
}

func defaultWordlistPath(envKey, fallback string) string {
	path := strings.TrimSpace(os.Getenv(envKey))
	if path == "" {
		path = fallback
	}
	return path
}

func resolveWordlist(path, envKey, fallback string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultWordlistPath(envKey, fallback)
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("wordlist not found: %s", path)
		}
		return "", fmt.Errorf("wordlist unavailable: %w", err)
	}
	return path, nil
}

func shellSplit(s string) ([]string, error) {
	var (
		args         []string
		current      strings.Builder
		quote        rune
		escaped      bool
		tokenStarted bool
	)

	flush := func() {
		if !tokenStarted {
			return
		}
		args = append(args, current.String())
		current.Reset()
		tokenStarted = false
	}

	for _, r := range s {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
			tokenStarted = true

		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				current.WriteRune(r)
				tokenStarted = true
			}

		case quote == '"':
			switch r {
			case '"':
				quote = 0
			case '\\':
				escaped = true
			default:
				current.WriteRune(r)
				tokenStarted = true
			}

		default:
			switch {
			case unicode.IsSpace(r):
				flush()
			case r == '\'' || r == '"':
				quote = r
				tokenStarted = true
			case r == '\\':
				escaped = true
				tokenStarted = true
			default:
				current.WriteRune(r)
				tokenStarted = true
			}
		}
	}

	if escaped {
		return nil, fmt.Errorf("unterminated escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()

	return args, nil
}

func NmapArgs(r dto.NmapRequest) ([]string, error) {
	scanType := r.ScanType
	if scanType == "" {
		scanType = "-sCV"
	}
	scanParts, err := splitArgs(scanType)
	if err != nil {
		return nil, fmt.Errorf("invalid scan_type: %w", err)
	}
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-T4 -Pn"
	}

	args := append([]string{"nmap"}, scanParts...)
	if r.Ports != "" {
		args = append(args, "-p", r.Ports)
	}
	args, err = appendSplitArgs(args, extra, "additional_args")
	if err != nil {
		return nil, err
	}
	args = append(args, r.Target)
	return args, nil
}

func GobusterArgs(r dto.GobusterRequest) ([]string, error) {
	mode := r.Mode
	if mode == "" {
		mode = "dir"
	}
	wordlist, err := resolveWordlist(r.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}

	args := []string{"gobuster", mode, "-u", r.URL, "-w", wordlist}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func DirbArgs(r dto.DirbRequest) ([]string, error) {
	wordlist, err := resolveWordlist(r.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	args := []string{"dirb", r.URL, wordlist}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func NiktoArgs(r dto.NiktoRequest) ([]string, error) {
	args := []string{"nikto", "-h", r.Target}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func TsharkArgs(r dto.TsharkRequest) ([]string, error) {
	readFile := strings.TrimSpace(r.ReadFile)
	iface := strings.TrimSpace(r.Interface)
	switch {
	case readFile == "" && iface == "":
		return nil, fmt.Errorf("read_file or interface is required")
	case readFile != "" && iface != "":
		return nil, fmt.Errorf("read_file and interface cannot be used together")
	}

	args := []string{"tshark"}

	if readFile != "" {
		args = append(args, "-r", readFile)
	} else {
		args = append(args, "-i", iface)
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
		for field := range strings.SplitSeq(r.OutputFields, ",") {
			trimmed := strings.TrimSpace(field)
			if trimmed != "" {
				args = append(args, "-e", trimmed)
			}
		}
	}

	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func SQLMapArgs(r dto.SQLMapRequest) ([]string, error) {
	args := []string{"sqlmap", "-u", r.URL, "--batch"}
	if r.Data != "" {
		args = append(args, "--data", r.Data)
	}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func MetasploitScript(r dto.MetasploitRequest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "use %s\n", r.Module)
	optionKeys := make([]string, 0, len(r.Options))
	for k := range r.Options {
		optionKeys = append(optionKeys, k)
	}
	sort.Strings(optionKeys)
	for _, k := range optionKeys {
		v := r.Options[k]
		fmt.Fprintf(&sb, "set %s %s\n", k, v)
	}
	sb.WriteString(metasploitAction(r.Module))
	sb.WriteString("\nexit -y\n")
	return sb.String()
}

func metasploitAction(module string) string {
	trimmed := strings.TrimSpace(module)
	if strings.HasPrefix(trimmed, "auxiliary/") || strings.HasPrefix(trimmed, "post/") {
		return "run"
	}
	return "exploit"
}

func MetasploitArgs(rcFile string) []string {
	return []string{"msfconsole", "-q", "-r", rcFile}
}

func HydraArgs(r dto.HydraRequest) ([]string, error) {
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
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func JohnArgs(r dto.JohnRequest) ([]string, error) {
	wordlist, err := resolveWordlist(r.Wordlist, defaultJohnWordlistEnv, defaultJohnWordlist)
	if err != nil {
		return nil, err
	}
	args := []string{"john"}
	if r.Format != "" {
		args = append(args, "--format="+r.Format)
	}
	args = append(args, "--wordlist="+wordlist)
	args, err = appendSplitArgs(args, r.AdditionalArgs, "additional_args")
	if err != nil {
		return nil, err
	}
	return append(args, r.HashFile), nil
}

func WPScanArgs(r dto.WPScanRequest) ([]string, error) {
	args := []string{"wpscan", "--url", r.URL}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func Enum4linuxArgs(r dto.Enum4linuxRequest) ([]string, error) {
	extra := r.AdditionalArgs
	if extra == "" {
		extra = "-a"
	}
	args := []string{"enum4linux"}
	args, err := appendSplitArgs(args, extra, "additional_args")
	if err != nil {
		return nil, err
	}
	return append(args, r.Target), nil
}
func ValidGobusterMode(mode string) bool {
	switch mode {
	case "", "dir", "dns", "fuzz", "vhost":
		return true
	}
	return false
}
