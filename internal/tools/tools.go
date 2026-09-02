package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	defaultDirWordlistEnv  = "KALI_MCP_DIR_WORDLIST"
	defaultDirWordlist     = "/usr/share/wordlists/dirb/common.txt"
	smallDirWordlistEnv    = "KALI_MCP_SMALL_DIR_WORDLIST"
	smallDirWordlist       = "/usr/share/wordlists/dirb/small.txt"
	defaultJohnWordlistEnv = "KALI_MCP_JOHN_WORDLIST"
	defaultJohnWordlist    = "/usr/share/wordlists/rockyou.txt"
	nucleiTemplatesEnv     = "KALI_MCP_NUCLEI_TEMPLATES"
)

func DefaultDirWordlistPath() string {
	return defaultWordlistPath(defaultDirWordlistEnv, defaultDirWordlist)
}

func DefaultJohnWordlistPath() string {
	return defaultWordlistPath(defaultJohnWordlistEnv, defaultJohnWordlist)
}

func SmallDirWordlistPath() string {
	return defaultWordlistPath(smallDirWordlistEnv, smallDirWordlist)
}

func NucleiTemplatesPath() string {
	if path := strings.TrimSpace(os.Getenv(nucleiTemplatesEnv)); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "nuclei-templates")
}

func NucleiTemplatesReady() bool {
	info, err := os.Stat(filepath.Join(NucleiTemplatesPath(), ".checksum"))
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
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

func ValidGobusterMode(mode string) bool {
	switch mode {
	case "", "dir", "dns", "fuzz", "vhost":
		return true
	}
	return false
}
