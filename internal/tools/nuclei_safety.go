package tools

import (
	"fmt"
	"strings"
)

var safeNucleiAdditionalFlags = map[string]bool{
	"H":                     true,
	"header":                true,
	"timeout":               true,
	"max-redirects":         true,
	"response-size-read":    true,
	"response-size-save":    true,
	"stats-interval":        true,
	"silent":                false,
	"nc":                    false,
	"no-color":              false,
	"nm":                    false,
	"no-meta":               false,
	"ts":                    false,
	"timestamp":             false,
	"ms":                    false,
	"matcher-status":        false,
	"stats":                 false,
	"hm":                    false,
	"hang-monitor":          false,
	"debug":                 false,
	"dreq":                  false,
	"debug-req":             false,
	"dresp":                 false,
	"debug-resp":            false,
	"duc":                   false,
	"disable-update-check":  false,
	"spm":                   false,
	"stop-at-first-match":   false,
	"dr":                    false,
	"disable-redirects":     false,
	"fr":                    false,
	"follow-redirects":      false,
	"fhr":                   false,
	"follow-host-redirects": false,
	"dc":                    false,
	"disable-clustering":    false,
	"no-stdin":              false,
}

func validateSafeNucleiAdditionalArgs(value string) error {
	args, err := shellSplit(value)
	if err != nil {
		return err
	}
	for index := 0; index < len(args); index++ {
		name, inlineValue, ok := nucleiFlag(args[index])
		if !ok {
			return fmt.Errorf("Nuclei additional_args contains positional value %q", args[index])
		}
		requiresValue, allowed := safeNucleiAdditionalFlags[name]
		if !allowed {
			return fmt.Errorf("Nuclei additional_args flag %q requires allow_unsafe", args[index])
		}
		if !requiresValue && inlineValue {
			return fmt.Errorf("Nuclei additional_args flag %q does not accept an inline value", args[index])
		}
		if !requiresValue || inlineValue {
			continue
		}
		index++
		if index >= len(args) || strings.HasPrefix(args[index], "-") {
			return fmt.Errorf("Nuclei additional_args flag %q requires a value", name)
		}
	}
	return nil
}

func nucleiFlag(argument string) (name string, inlineValue, ok bool) {
	if !strings.HasPrefix(argument, "-") {
		return "", false, false
	}
	name = strings.TrimLeft(argument, "-")
	if before, _, found := strings.Cut(name, "="); found {
		name = before
		inlineValue = true
	}
	if name != "H" {
		name = strings.ToLower(name)
	}
	return name, inlineValue, name != ""
}
