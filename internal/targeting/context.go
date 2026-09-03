package targeting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

var (
	errInvalidTargetContext = errors.New("invalid target context")
	errExpiredTargetContext = errors.New("target context has expired")
)

const targetContextExpiryWarning = time.Minute

type targetContextClaims struct {
	ResolutionID  string          `json:"resolution_id"`
	Original      string          `json:"original"`
	BrowserTarget string          `json:"browser_target,omitempty"`
	NetworkTarget string          `json:"network_target"`
	Port          int             `json:"port,omitempty"`
	Scope         dto.TargetScope `json:"scope"`
	ExpiresAt     int64           `json:"expires_at"`
}

func attachTargetContexts(secret string, result *dto.TargetResolutionResult, issued issuedResolutionReceipt) error {
	for index := range result.Candidates {
		candidate := &result.Candidates[index]
		if !candidate.Selectable {
			continue
		}
		context, err := signTargetContext(secret, targetContextClaims{
			ResolutionID:  issued.ID,
			Original:      result.OriginalTarget,
			BrowserTarget: candidate.BrowserTarget,
			NetworkTarget: candidate.NetworkTarget,
			Port:          candidate.Port,
			Scope:         candidate.Scope,
			ExpiresAt:     issued.ExpiresAt.Unix(),
		})
		if err != nil {
			return err
		}
		candidate.TargetContext = context
		candidate.ContextExpiresAt = issued.ExpiresAt
	}
	return nil
}

func signTargetContext(secret string, claims targetContextClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode target context: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encodedPayload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encodedPayload + "." + signature, nil
}

func verifyTargetContext(secret, context string, now time.Time) (targetContextClaims, error) {
	encodedPayload, encodedSignature, found := strings.Cut(context, ".")
	if !found {
		return targetContextClaims{}, errInvalidTargetContext
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return targetContextClaims{}, errInvalidTargetContext
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encodedPayload))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return targetContextClaims{}, errInvalidTargetContext
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return targetContextClaims{}, errInvalidTargetContext
	}
	var claims targetContextClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return targetContextClaims{}, errInvalidTargetContext
	}
	if claims.ResolutionID == "" || claims.Original == "" || claims.NetworkTarget == "" || claims.Port < 0 || claims.Port > 65535 {
		return targetContextClaims{}, errInvalidTargetContext
	}
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return targetContextClaims{}, errExpiredTargetContext
	}
	return claims, nil
}
