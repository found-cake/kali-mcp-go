package toolapi

import (
	"fmt"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func validateJWTRequest(request dto.JWTRequest) error {
	if request.Token == "" {
		return fmt.Errorf("token is required")
	}
	switch request.Mode {
	case "", "pb", "er", "at":
	default:
		return fmt.Errorf("mode must be pb|er|at")
	}
	if request.TargetURL == "" {
		if request.RequestHeader != "" || request.RequestCookie != "" {
			return fmt.Errorf("target_url is required with request_header or request_cookie")
		}
		return nil
	}
	if (request.RequestHeader == "") == (request.RequestCookie == "") {
		return fmt.Errorf("exactly one of request_header or request_cookie is required for a live target")
	}
	template := request.RequestHeader
	if template == "" {
		template = request.RequestCookie
	}
	if strings.Count(template, "JWT_HERE") != 1 {
		return fmt.Errorf("live request template must contain JWT_HERE exactly once")
	}
	return nil
}
