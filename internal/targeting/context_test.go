package targeting

import (
	"errors"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestTargetContextRejectsTamperedAndExpiredTokens(t *testing.T) {
	// Given: valid claims signed once for a live token and once for an expired token.
	now := time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC)
	claims := targetContextClaims{
		ResolutionID: "resolution-1", Original: "http://127.0.0.1:3000/",
		BrowserTarget: "http://host.docker.internal:3000/", NetworkTarget: "host.docker.internal",
		Scope: dto.TargetScopeDockerHost, ExpiresAt: now.Add(time.Minute).Unix(),
	}
	valid, err := signTargetContext("secret", claims)
	if err != nil {
		t.Fatalf("sign valid context: %v", err)
	}
	claims.ExpiresAt = now.Add(-time.Second).Unix()
	expired, err := signTargetContext("secret", claims)
	if err != nil {
		t.Fatalf("sign expired context: %v", err)
	}

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{name: "tampered", token: valid + "x", want: errInvalidTargetContext},
		{name: "expired", token: expired, want: errExpiredTargetContext},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When: verification receives an invalid target context state.
			_, err := verifyTargetContext("secret", test.token, now)

			// Then: verification fails closed with the established sentinel.
			if !errors.Is(err, test.want) {
				t.Fatalf("verify target context: got %v, want %v", err, test.want)
			}
		})
	}
}
