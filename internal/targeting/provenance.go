package targeting

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func ValidateHealthURL(healthURL string, provenance *dto.TargetProvenance) error {
	if healthURL == "" {
		return nil
	}
	if provenance == nil || strings.TrimSpace(provenance.Selected) == "" {
		return fmt.Errorf("health_url requires a target-bound request")
	}
	parsed, err := url.Parse(healthURL)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("health_url must be an HTTP or HTTPS URL")
	}
	if selectedOrigin, ok := Origin(provenance.Selected); ok {
		healthOrigin, _ := Origin(healthURL)
		if healthOrigin != selectedOrigin {
			return fmt.Errorf("health_url must use the selected target origin")
		}
		return nil
	}
	selectedHost := strings.Trim(strings.TrimSpace(provenance.Selected), "[]")
	if host, _, splitErr := net.SplitHostPort(provenance.Selected); splitErr == nil {
		selectedHost = strings.Trim(host, "[]")
	}
	if !strings.EqualFold(parsed.Hostname(), selectedHost) {
		return fmt.Errorf("health_url must use the selected target host")
	}
	if provenance.Port > 0 && healthURLPort(parsed) != provenance.Port {
		return fmt.Errorf("health_url must use the selected target port %d", provenance.Port)
	}
	return nil
}

func healthURLPort(parsed *url.URL) int {
	if parsed.Port() != "" {
		port, _ := strconv.Atoi(parsed.Port())
		return port
	}
	if parsed.Scheme == "http" {
		return 80
	}
	return 443
}

func ResolveProvenance(request any, secret string, now time.Time) (*dto.TargetProvenance, error) {
	scanRequest, ok := request.(dto.ScanRequest)
	if ok && scanRequest.GetScanOptions().ResolutionReceipt != "" {
		if err := rejectResolvedVirtualHost(request); err != nil {
			return nil, err
		}
	}
	if ok && scanRequest.GetScanOptions().TargetContext != "" {
		claims, err := verifyTargetContext(secret, scanRequest.GetScanOptions().TargetContext, now)
		if err != nil {
			return nil, err
		}
		target := tools.RequestTarget(request)
		if sqlmapRequest, sqlmap := request.(dto.SQLMapRequest); sqlmap && (sqlmapRequest.RawRequest != "" || sqlmapRequest.RequestFile != "") {
			target, err = sqlMapContextTarget(sqlmapRequest, claims)
			if err != nil {
				return nil, err
			}
		}
		if target == "" {
			return nil, errResolutionTargetMismatch
		}
		if target != claims.NetworkTarget && !sameWebOrigin(target, claims.BrowserTarget) {
			return nil, errResolutionTargetMismatch
		}
		expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
		expiresIn := max(int64(expiresAt.Sub(now)/time.Second), 0)
		return &dto.TargetProvenance{
			Original: claims.Original, Selected: target, ResolutionID: claims.ResolutionID,
			SelectionReason: "target_context", Verified: true, Scope: claims.Scope, Port: claims.Port,
			ContextExpiresAt: expiresAt, ExpiresInSeconds: expiresIn,
			ExpiringSoon: expiresIn <= int64(targetContextExpiryWarning/time.Second),
		}, nil
	}
	target := tools.RequestTarget(request)
	if sqlmapRequest, sqlmap := request.(dto.SQLMapRequest); sqlmap && (sqlmapRequest.RawRequest != "" || sqlmapRequest.RequestFile != "") {
		var err error
		target, err = sqlMapRequestTarget(sqlmapRequest)
		if err != nil {
			return nil, err
		}
	}
	if target == "" {
		return nil, nil
	}
	if !ok || scanRequest.GetScanOptions().ResolutionReceipt == "" {
		if tools.IsLoopbackTarget(target) {
			return nil, errResolutionRequired
		}
		return &dto.TargetProvenance{Original: target, Selected: target, SelectionReason: "unverified_direct_target"}, nil
	}
	return verifyResolutionReceipt(secret, scanRequest.GetScanOptions().ResolutionReceipt, target, now)
}

func rejectResolvedVirtualHost(request any) error {
	switch value := request.(type) {
	case dto.HTTPRequest:
		return rejectExplicitHostHeader(value.Headers)
	case dto.SQLMapRequest:
		return rejectExplicitHostHeader(value.Headers)
	case dto.JWTRequest:
		return rejectHostHeaderText(value.RequestHeader)
	default:
		return nil
	}
}

func sameWebOrigin(selected, candidate string) bool {
	selectedOrigin, selectedOK := Origin(selected)
	candidateOrigin, candidateOK := Origin(candidate)
	return selectedOK && candidateOK && selectedOrigin == candidateOrigin
}

func Warnings(request any, provenance *dto.TargetProvenance) []string {
	warnings := tools.TargetWarnings(request)
	if provenance != nil && !provenance.Verified {
		warnings = append(warnings, "target was not verified by resolve_target")
	}
	if provenance != nil && provenance.ExpiringSoon {
		warnings = append(warnings, "target context expires soon; call resolve_target again and explicitly reselect the candidate")
	}
	return warnings
}
