package tools

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func JWTToolArgs(request dto.JWTRequest) ([]string, error) {
	extra, err := splitArgs(request.AdditionalArgs)
	if err != nil {
		return nil, fmt.Errorf("invalid additional_args: %w", err)
	}
	if err := rejectArguments(extra, "additional_args", "use the typed mode and allow_unsafe fields", "-M", "--mode"); err != nil {
		return nil, err
	}
	if err := rejectTargetSourceArgs(extra, "additional_args", false, "-t", "-r", "--request"); err != nil {
		return nil, err
	}
	args := []string{"jwt_tool", request.Token}
	if request.TargetURL != "" {
		args = append(args, "-t", request.TargetURL, "-np")
	}
	if request.RequestHeader != "" {
		args = append(args, "-rh", strings.Replace(request.RequestHeader, "JWT_HERE", request.Token, 1))
	}
	if request.RequestCookie != "" {
		args = append(args, "-rc", strings.Replace(request.RequestCookie, "JWT_HERE", request.Token, 1))
	}
	if request.Canary != "" {
		args = append(args, "-cv", request.Canary)
	}
	mode := request.Mode
	if mode == "" && request.TargetURL != "" {
		mode = "er"
	}
	if err := validateJWTMode(mode); err != nil {
		return nil, err
	}
	if (mode == "pb" || mode == "at") && !request.AllowUnsafe {
		return nil, fmt.Errorf("mode %s requires allow_unsafe because it includes command-injection timing probes", mode)
	}
	if mode != "" {
		args = append(args, "-M", mode)
	}
	if request.PublicKey != "" {
		args = append(args, "-pk", request.PublicKey)
	}
	return append(args, extra...), nil
}

func validateJWTMode(mode string) error {
	switch mode {
	case "", "pb", "er", "at":
		return nil
	default:
		return fmt.Errorf("mode must be pb|er|at")
	}
}
