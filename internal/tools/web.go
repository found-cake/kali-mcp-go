package tools

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	safeNiktoPlugins = "headers;httpoptions;ssl;cookies;robots;favicon;msgs;outdated;springboot;optionsbleed"
	safeNiktoPause   = 0.2
	niktoFinishGrace = 5
)

var niktoPluginName = regexp.MustCompile(`^[a-z0-9_]+$`)

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
	extra, err := splitArgs(r.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	if isDiscoveryProfile(r.Profile) || hasResolvedTarget(r.ScanOptions) {
		if err := rejectArguments(extra, "additional_args", "discovery profiles and resolved targets forbid proxy routing", "-p"); err != nil {
			return nil, err
		}
	}
	return appendTargetSafeArgs([]string{"dirb", r.URL, wordlist, "-S"}, r.AdditionalArgs, "additional_args", false, "-resume")
}

func NiktoArgs(r dto.NiktoRequest) ([]string, error) {
	extra, err := splitArgs(r.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	if err := rejectArguments(extra, "additional_args", "use the typed Nikto request controls", "-timeout", "-Option", "-option", "-Plugins", "-plugins"); err != nil {
		return nil, err
	}
	if hasResolvedTarget(r.ScanOptions) {
		if err := rejectTargetSourceArgs(extra, "additional_args", false, "-vhost", "-followredirects", "-useproxy"); err != nil {
			return nil, err
		}
	}
	if r.Profile == dto.ProfileWebDiscoveryLowRate {
		tuning := strings.TrimSpace(strings.ToLower(r.Tuning))
		if !strings.HasPrefix(tuning, "x") && strings.ContainsAny(tuning, "68") {
			return nil, fmt.Errorf("Nikto tuning 6 and 8 require explicit-custom")
		}
		if err := rejectArguments(extra, "additional_args", "Nikto tuning must use the validated tuning field; redirects and proxies are disabled", "-Tuning", "-tuning", "-followredirects", "-useproxy"); err != nil {
			return nil, err
		}
		if r.PauseSeconds > 0 && r.PauseSeconds < safeNiktoPause {
			return nil, fmt.Errorf("pause_seconds below %.1f is not permitted by web-discovery-low-rate", safeNiktoPause)
		}
	}
	plugins, err := niktoPlugins(r)
	if err != nil {
		return nil, err
	}
	args := []string{"nikto", "-h", r.Target, "-nocheck", "-nointeractive"}
	pause := r.PauseSeconds
	if r.Profile == dto.ProfileWebDiscoveryLowRate && pause == 0 {
		pause = safeNiktoPause
	}
	if pause > 0 {
		args = append(args, "-Pause", strconv.FormatFloat(pause, 'f', -1, 64))
	}
	maxTime, err := niktoMaxTime(r)
	if err != nil {
		return nil, err
	}
	if maxTime != "" {
		args = append(args, "-maxtime", maxTime)
	}
	if r.RequestTimeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(r.RequestTimeout))
	}
	if r.FailureLimit > 0 {
		args = append(args, "-Option", "FAILURES="+strconv.Itoa(r.FailureLimit))
	}
	if r.Tuning != "" {
		args = append(args, "-Tuning", r.Tuning)
	}
	if plugins != "" {
		args = append(args, "-Plugins", plugins)
	}
	return appendTargetSafeArgs(args, r.AdditionalArgs, "additional_args", false, "-h", "-host", "-url", "-config")
}

func niktoMaxTime(request dto.NiktoRequest) (string, error) {
	if request.Profile != dto.ProfileWebDiscoveryLowRate {
		return request.MaxTime, nil
	}
	outerSeconds := request.Timeout
	if outerSeconds <= 0 {
		outerSeconds = dto.DefaultTimeoutSeconds
	}
	maximumSeconds := max(1, outerSeconds-niktoFinishGrace)
	if request.MaxTime == "" {
		return strconv.Itoa(maximumSeconds) + "s", nil
	}
	duration, err := time.ParseDuration(request.MaxTime)
	if err != nil || duration <= 0 {
		return "", fmt.Errorf("invalid Nikto max_time %q; use a positive duration such as 120s or 10m", request.MaxTime)
	}
	if duration > time.Duration(maximumSeconds)*time.Second {
		return "", fmt.Errorf("max_time must be at most %ds with timeout=%ds under web-discovery-low-rate", maximumSeconds, outerSeconds)
	}
	return request.MaxTime, nil
}

func niktoPlugins(request dto.NiktoRequest) (string, error) {
	plugins := request.Plugins
	if request.Profile == dto.ProfileWebDiscoveryLowRate && len(plugins) == 0 {
		return safeNiktoPlugins, nil
	}
	allowed := make(map[string]bool)
	if request.Profile == dto.ProfileWebDiscoveryLowRate {
		for name := range strings.SplitSeq(safeNiktoPlugins, ";") {
			allowed[name] = true
		}
	}
	for _, name := range plugins {
		if !niktoPluginName.MatchString(name) {
			return "", fmt.Errorf("invalid Nikto plugin name %q", name)
		}
		if request.Profile == dto.ProfileWebDiscoveryLowRate && !allowed[name] {
			return "", fmt.Errorf("Nikto plugin %q is not permitted by web-discovery-low-rate", name)
		}
	}
	return strings.Join(plugins, ";"), nil
}

func WPScanArgs(r dto.WPScanRequest) ([]string, error) {
	if err := rejectContextHostHeaders(r.ScanOptions, r.AdditionalArgs, "additional_args", "--headers"); err != nil {
		return nil, err
	}
	if hasResolvedTarget(r.ScanOptions) {
		extra, err := splitArgs(r.AdditionalArgs)
		if err != nil {
			return nil, fmt.Errorf("invalid additional_args: %w", err)
		}
		if err := rejectArguments(extra, "additional_args", "resolved targets forbid proxy routing", "--proxy", "--proxy-auth"); err != nil {
			return nil, err
		}
	}
	return appendTargetSafeArgs([]string{"wpscan", "--url", r.URL}, r.AdditionalArgs, "additional_args", false, "--url", "--config-file")
}
