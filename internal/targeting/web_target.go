package targeting

import (
	"fmt"
	"net/url"
	"strings"
)

func setWebTarget(current *string, expected, original string) error {
	if expected == "" {
		return fmt.Errorf("target_context does not contain a browser target")
	}
	if *current == "" {
		*current = expected
		return nil
	}
	currentOrigin, currentOK := Origin(*current)
	expectedOrigin, expectedOK := Origin(expected)
	if currentOK && expectedOK && currentOrigin == expectedOrigin {
		return nil
	}
	originalOrigin, originalOK := Origin(original)
	if !currentOK || !expectedOK || !originalOK || currentOrigin != originalOrigin {
		return fmt.Errorf("request URL does not match target_context browser origin; use the selected candidate browser_target %s or omit the request URL", expected)
	}
	if *current == original {
		*current = expected
		return nil
	}
	currentURL, _ := url.Parse(*current)
	expectedURL, _ := url.Parse(expected)
	expectedURL.Path = currentURL.Path
	expectedURL.RawPath = currentURL.RawPath
	expectedURL.ForceQuery = currentURL.ForceQuery
	expectedURL.RawQuery = currentURL.RawQuery
	expectedURL.Fragment = currentURL.Fragment
	expectedURL.RawFragment = currentURL.RawFragment
	*current = expectedURL.String()
	return nil
}

func setURLOrHostTarget(current *string, claims targetContextClaims) error {
	if *current != "" && !strings.Contains(*current, "://") {
		if claims.BrowserTarget != "" && claims.Port > 0 {
			if !strings.EqualFold(strings.Trim(strings.TrimSpace(*current), "[]"), strings.Trim(strings.TrimSpace(claims.NetworkTarget), "[]")) {
				return fmt.Errorf("request target does not match target_context network target")
			}
			*current = claims.BrowserTarget
			return nil
		}
		return setNetworkTarget(current, claims.NetworkTarget)
	}
	if claims.BrowserTarget != "" {
		return setWebTarget(current, claims.BrowserTarget, claims.Original)
	}
	return setNetworkTarget(current, claims.NetworkTarget)
}
