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
	targetFlag := "-u"
	if mode == "dns" {
		targetFlag = "--domain"
	}
	args := []string{"gobuster", mode, targetFlag, r.URL, "-w", wordlist, "--quiet", "--no-progress", "--no-color"}
	return appendTargetSafeArgs(args, r.AdditionalArgs, "additional_args", false, "-u", "--url", "--domain", "--do")
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
	return appendTargetSafeArgs(args, r.AdditionalArgs, "additional_args", false, "-h", "-host", "-config")
}

func WPScanArgs(r dto.WPScanRequest) ([]string, error) {
	return appendTargetSafeArgs([]string{"wpscan", "--url", r.URL}, r.AdditionalArgs, "additional_args", false, "--url", "--config-file")
}
