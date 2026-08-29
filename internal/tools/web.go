package tools

import (
	"strconv"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func GobusterArgs(r dto.GobusterRequest) ([]string, error) {
	mode := r.Mode
	if mode == "" {
		mode = "dir"
	}
	wordlist, err := resolveWordlist(r.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	return appendSplitArgs([]string{"gobuster", mode, "-u", r.URL, "-w", wordlist}, r.AdditionalArgs, "additional_args")
}

func DirbArgs(r dto.DirbRequest) ([]string, error) {
	wordlist, err := resolveWordlist(r.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	return appendSplitArgs([]string{"dirb", r.URL, wordlist}, r.AdditionalArgs, "additional_args")
}

func NiktoArgs(r dto.NiktoRequest) ([]string, error) {
	args := []string{"nikto", "-h", r.Target, "-nocheck", "-nointeractive"}
	if r.PauseSeconds > 0 {
		args = append(args, "-Pause", strconv.FormatFloat(r.PauseSeconds, 'f', -1, 64))
	}
	if r.MaxTime != "" {
		args = append(args, "-maxtime", r.MaxTime)
	}
	if r.Tuning != "" {
		args = append(args, "-Tuning", r.Tuning)
	}
	return appendSplitArgs(args, r.AdditionalArgs, "additional_args")
}

func WPScanArgs(r dto.WPScanRequest) ([]string, error) {
	return appendSplitArgs([]string{"wpscan", "--url", r.URL}, r.AdditionalArgs, "additional_args")
}
