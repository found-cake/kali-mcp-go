package toolapi

import (
	"fmt"

	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const maximumRetireScriptURLs = 64

func validateRetireRequest(request dto.RetireRequest) error {
	provided := 0
	for _, selected := range []bool{request.Path != "", request.URL != "", len(request.ScriptURLs) > 0} {
		if selected {
			provided++
		}
	}
	if provided != 1 {
		return fmt.Errorf("provide exactly one of path, url, or script_urls")
	}
	if request.Path != "" && len(request.Headers) > 0 {
		return fmt.Errorf("headers are only used for url or script_urls downloads")
	}
	if err := validateAuthenticatedHeaders(request.Headers); err != nil {
		return err
	}
	if len(request.ScriptURLs) == 0 {
		return nil
	}
	if request.TargetContext == "" {
		return fmt.Errorf("script_urls requires target_context from resolve_target")
	}
	if len(request.ScriptURLs) > maximumRetireScriptURLs {
		return fmt.Errorf("script_urls must contain at most %d URLs", maximumRetireScriptURLs)
	}
	origin := ""
	for _, address := range request.ScriptURLs {
		currentOrigin, ok := targeting.Origin(address)
		if !ok {
			return fmt.Errorf("script_urls must contain HTTP or HTTPS URLs without userinfo")
		}
		if origin == "" {
			origin = currentOrigin
		} else if origin != currentOrigin {
			return fmt.Errorf("script_urls must share one origin")
		}
	}
	return nil
}
