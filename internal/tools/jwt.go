package tools

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func JWTToolArgs(request dto.JWTRequest) ([]string, error) {
	args := []string{"jwt_tool", request.Token}
	if request.TargetURL != "" {
		args = append(args, "-t", request.TargetURL)
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
		mode = "at"
	}
	if err := validateJWTMode(mode); err != nil {
		return nil, err
	}
	if mode != "" {
		args = append(args, "-M", mode)
	}
	if request.PublicKey != "" {
		args = append(args, "-pk", request.PublicKey)
	}
	return appendTargetSafeArgs(args, request.AdditionalArgs, "additional_args", false, "-t", "-r", "--request")
}

func validateJWTMode(mode string) error {
	switch mode {
	case "", "pb", "er", "at":
		return nil
	default:
		return fmt.Errorf("mode must be pb|er|at")
	}
}
