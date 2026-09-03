package tools

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func GobusterArgs(r dto.GobusterRequest) ([]string, error) {
	mode := r.Mode
	if mode == "" {
		mode = "dir"
	}
	if hasResolvedTarget(r.ScanOptions) && mode == "vhost" {
		return nil, fmt.Errorf("Gobuster vhost mode is not permitted with a resolved target")
	}
	if err := rejectContextHostHeaders(r.ScanOptions, r.AdditionalArgs, "additional_args", "-H", "--headers"); err != nil {
		return nil, err
	}
	wordlist, err := resolveWordlist(r.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	extra, err := splitArgs(r.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	if isDiscoveryProfile(r.Profile) {
		if err := rejectArguments(extra, "additional_args", "discovery profiles use Gobuster's default GET request", "-m", "--method", "-r", "--follow-redirect", "--proxy"); err != nil {
			return nil, err
		}
	}
	if hasResolvedTarget(r.ScanOptions) {
		if err := rejectArguments(extra, "additional_args", "resolved targets forbid proxy destinations and cross-host redirects", "--proxy", "-r", "--follow-redirect"); err != nil {
			return nil, err
		}
	}
	targetFlag := "-u"
	if mode == "dns" {
		targetFlag = "--domain"
	}
	args := []string{"gobuster", mode, targetFlag, r.URL, "-w", wordlist, "--quiet", "--no-progress", "--no-color"}
	return appendTargetSafeArgs(args, r.AdditionalArgs, "additional_args", false, "-u", "--url", "--domain", "--do", "-w", "--wordlist")
}

func DirbArgs(r dto.DirbRequest) ([]string, error) {
	if err := rejectContextHostHeaders(r.ScanOptions, r.AdditionalArgs, "additional_args", "-H"); err != nil {
		return nil, err
	}
	wordlist, err := resolveWordlist(r.Wordlist, defaultDirWordlistEnv, defaultDirWordlist)
	if err != nil {
		return nil, err
	}
	return appendSplitArgs([]string{"dirb", r.URL, wordlist}, r.AdditionalArgs, "additional_args")
}

func NiktoArgs(r dto.NiktoRequest) ([]string, error) {
	if hasResolvedTarget(r.ScanOptions) {
		extra, err := splitArgs(r.AdditionalArgs)
		if err != nil {
			return nil, fmt.Errorf("invalid additional_args: %w", err)
		}
		if err := rejectTargetSourceArgs(extra, "additional_args", false, "-vhost", "-followredirects"); err != nil {
			return nil, err
		}
	}
	if r.Profile == dto.ProfileWebDiscoveryLowRate {
		tuning := strings.TrimSpace(strings.ToLower(r.Tuning))
		if !strings.HasPrefix(tuning, "x") && strings.ContainsAny(tuning, "68") {
			return nil, fmt.Errorf("Nikto tuning 6 and 8 require explicit-custom")
		}
		extra, err := splitArgs(r.AdditionalArgs)
		if err != nil {
			return nil, fmt.Errorf("invalid additional_args: %w", err)
		}
		if err := rejectArguments(extra, "additional_args", "Nikto tuning must use the validated tuning field; redirects and proxies are disabled", "-Tuning", "-tuning", "-followredirects", "-useproxy"); err != nil {
			return nil, err
		}
	}
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
	return appendTargetSafeArgs(args, r.AdditionalArgs, "additional_args", false, "-h", "-host", "-url", "-config")
}

func WPScanArgs(r dto.WPScanRequest) ([]string, error) {
	if err := rejectContextHostHeaders(r.ScanOptions, r.AdditionalArgs, "additional_args", "--headers"); err != nil {
		return nil, err
	}
	return appendTargetSafeArgs([]string{"wpscan", "--url", r.URL}, r.AdditionalArgs, "additional_args", false, "--url", "--config-file")
}
