package targeting

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	resolutionReceiptLifetime = 10 * time.Minute
	maximumResolutionLifetime = time.Hour
)

var (
	errResolutionRequired       = errors.New("target resolution is required for loopback targets")
	errInvalidResolutionReceipt = errors.New("invalid target resolution receipt")
	errExpiredResolutionReceipt = errors.New("target resolution receipt has expired")
	errResolutionTargetMismatch = errors.New("selected target is not present in the resolution receipt")
)

type resolutionReceiptClaims struct {
	ResolutionID       string                       `json:"resolution_id"`
	Original           string                       `json:"original"`
	Candidates         []resolutionReceiptCandidate `json:"candidates"`
	Recommended        string                       `json:"recommended,omitempty"`
	RecommendedTargets []string                     `json:"recommended_targets,omitempty"`
	ExpiresAt          int64                        `json:"expires_at"`
}

type resolutionReceiptCandidate struct {
	Target        string          `json:"target"`
	BrowserTarget string          `json:"browser_target,omitempty"`
	NetworkTarget string          `json:"network_target"`
	Port          int             `json:"port,omitempty"`
	Scope         dto.TargetScope `json:"scope,omitempty"`
}

type issuedResolutionReceipt struct {
	Token     string
	ID        string
	ExpiresAt time.Time
}

func issueResolutionReceipt(secret string, result dto.TargetResolutionResult, now time.Time) (issuedResolutionReceipt, error) {
	return issueResolutionReceiptUntil(secret, result, now.Add(resolutionReceiptLifetime))
}

func Lifetime(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return resolutionReceiptLifetime, nil
	}
	lifetime := time.Duration(seconds) * time.Second
	if lifetime < time.Second || lifetime > maximumResolutionLifetime {
		return 0, fmt.Errorf("valid_for_seconds must be between 1 and 3600")
	}
	return lifetime, nil
}

func AttachResolution(secret string, result *dto.TargetResolutionResult, expiresAt time.Time) error {
	issued, err := issueResolutionReceiptUntil(secret, *result, expiresAt)
	if err != nil {
		return err
	}
	result.ResolutionID = issued.ID
	result.ResolutionReceipt = issued.Token
	result.ReceiptExpiresAt = issued.ExpiresAt
	return attachTargetContexts(secret, result, issued)
}

func issueResolutionReceiptUntil(secret string, result dto.TargetResolutionResult, expiresAt time.Time) (issuedResolutionReceipt, error) {
	identifier := make([]byte, 12)
	if _, err := rand.Read(identifier); err != nil {
		return issuedResolutionReceipt{}, fmt.Errorf("generate resolution id: %w", err)
	}
	expiresAt = expiresAt.UTC()
	resolutionID := hex.EncodeToString(identifier)
	claims := resolutionReceiptClaims{
		ResolutionID: resolutionID,
		Original:     result.OriginalTarget,
		Recommended:  result.RecommendedTarget,
		ExpiresAt:    expiresAt.Unix(),
		Candidates:   make([]resolutionReceiptCandidate, 0, len(result.Candidates)*3),
	}
	seenCandidates := make(map[string]bool)
	for _, candidate := range result.Candidates {
		if !candidate.Selectable {
			continue
		}
		for _, target := range []string{candidate.Target, candidate.BrowserTarget, candidate.NetworkTarget} {
			if target != "" && !seenCandidates[target] {
				claims.Candidates = append(claims.Candidates, resolutionReceiptCandidate{
					Target: target, BrowserTarget: candidate.BrowserTarget, NetworkTarget: candidate.NetworkTarget,
					Port: candidate.Port, Scope: candidate.Scope,
				})
				seenCandidates[target] = true
			}
		}
	}
	seenRecommended := make(map[string]bool)
	for _, target := range []string{result.RecommendedTarget, result.RecommendedBrowserTarget, result.RecommendedNetworkTarget} {
		if target != "" && !seenRecommended[target] {
			claims.RecommendedTargets = append(claims.RecommendedTargets, target)
			seenRecommended[target] = true
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return issuedResolutionReceipt{}, fmt.Errorf("encode resolution receipt: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encodedPayload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return issuedResolutionReceipt{Token: encodedPayload + "." + signature, ID: resolutionID, ExpiresAt: expiresAt}, nil
}

func verifyResolutionReceipt(secret, receipt, selected string, now time.Time) (*dto.TargetProvenance, error) {
	claims, matched, err := matchedResolutionReceiptCandidate(secret, receipt, selected, now)
	if err != nil {
		return nil, err
	}
	reason := "explicit_candidate"
	for _, recommended := range append([]string{claims.Recommended}, claims.RecommendedTargets...) {
		if selected == recommended && recommended != "" {
			reason = "only_reachable_candidate"
			break
		}
	}
	return &dto.TargetProvenance{
		Original: claims.Original, Selected: selected, ResolutionID: claims.ResolutionID,
		SelectionReason: reason, Verified: true, Scope: matched.Scope, Port: matched.Port,
	}, nil
}

func matchedResolutionReceiptCandidate(
	secret, receipt, selected string,
	now time.Time,
) (resolutionReceiptClaims, resolutionReceiptCandidate, error) {
	encodedPayload, encodedSignature, found := strings.Cut(receipt, ".")
	if !found || encodedPayload == "" || encodedSignature == "" {
		return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, errInvalidResolutionReceipt
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, fmt.Errorf("decode receipt signature: %w", errInvalidResolutionReceipt)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encodedPayload))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, errInvalidResolutionReceipt
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, fmt.Errorf("decode receipt payload: %w", errInvalidResolutionReceipt)
	}
	var claims resolutionReceiptClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, fmt.Errorf("parse receipt payload: %w", errInvalidResolutionReceipt)
	}
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, errExpiredResolutionReceipt
	}
	for _, candidate := range claims.Candidates {
		if resolutionCandidateMatches(candidate.Target, selected) {
			return claims, candidate, nil
		}
	}
	return resolutionReceiptClaims{}, resolutionReceiptCandidate{}, errResolutionTargetMismatch
}

func resolutionReceiptContext(secret, receipt, selected string, now time.Time) (targetContextClaims, error) {
	claims, candidate, err := matchedResolutionReceiptCandidate(secret, receipt, selected, now)
	if err != nil {
		return targetContextClaims{}, err
	}
	return targetContextClaims{
		ResolutionID: claims.ResolutionID, Original: claims.Original,
		BrowserTarget: candidate.BrowserTarget, NetworkTarget: candidate.NetworkTarget,
		Port: candidate.Port, Scope: candidate.Scope, ExpiresAt: claims.ExpiresAt,
	}, nil
}

func resolutionCandidateMatches(candidate, selected string) bool {
	if candidate == selected {
		return true
	}
	candidateOrigin, candidateOK := Origin(candidate)
	selectedOrigin, selectedOK := Origin(selected)
	return candidateOK && selectedOK && candidateOrigin == selectedOrigin
}

func Origin(target string) (string, bool) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return scheme + "://" + strings.ToLower(parsed.Hostname()) + ":" + port, true
}
