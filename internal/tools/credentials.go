package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func MetasploitScript(r dto.MetasploitRequest) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "use %s\n", r.Module)
	optionKeys := make([]string, 0, len(r.Options))
	for k := range r.Options {
		optionKeys = append(optionKeys, k)
	}
	sort.Strings(optionKeys)
	for _, k := range optionKeys {
		fmt.Fprintf(&sb, "set %s %s\n", k, r.Options[k])
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

func MetasploitArgs(rcFile string) []string { return []string{"msfconsole", "-q", "-r", rcFile} }

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
	args = append(args, rewriteLoopbackTarget(r.Target), r.Service)
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

var johnPlaintextLine = regexp.MustCompile(`(?m)^\S+\s+\(([^)]+)\)\s*$`)

func RedactJohnOutput(output string) string {
	return johnPlaintextLine.ReplaceAllString(output, "******** ($1)")
}

type JohnPlan struct {
	args    []string
	tempDir string
}

func PrepareJohn(request dto.JohnRequest) (*JohnPlan, error) {
	if (request.Hash == "") == (request.HashFile == "") {
		return nil, fmt.Errorf("provide exactly one of hash or hash_file")
	}
	tempDir, err := os.MkdirTemp("", "kali-mcp-john-*")
	if err != nil {
		return nil, fmt.Errorf("create john workspace: %w", err)
	}
	plan := &JohnPlan{tempDir: tempDir}
	if request.Hash != "" {
		request.HashFile = filepath.Join(tempDir, "hashes.txt")
		content := request.Hash
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if err := os.WriteFile(request.HashFile, []byte(content), 0o600); err != nil {
			plan.Cleanup()
			return nil, fmt.Errorf("write hash: %w", err)
		}
	}
	johnArgs, err := JohnArgs(request)
	if err != nil {
		plan.Cleanup()
		return nil, err
	}
	plan.args = append([]string{"env", "HOME=" + tempDir}, johnArgs...)
	return plan, nil
}

func (p *JohnPlan) Args() []string {
	return append([]string(nil), p.args...)
}

func (p *JohnPlan) Cleanup() {
	if p != nil && p.tempDir != "" {
		_ = os.RemoveAll(p.tempDir)
	}
}
