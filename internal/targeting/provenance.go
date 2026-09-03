package targeting

import (
	"time"

	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

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
