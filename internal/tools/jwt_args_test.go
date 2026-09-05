package tools

import (
	"reflect"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestJWTToolArgsSubstitutesTokenInLiveTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request dto.JWTRequest
		want    []string
	}{
		{
			name: "authorization header",
			request: dto.JWTRequest{
				Token: "header.payload.signature", TargetURL: "https://example.com/me",
				RequestHeader: "Authorization: Bearer JWT_HERE", Canary: "admin",
			},
			want: []string{"jwt_tool", "header.payload.signature", "-t", "https://example.com/me", "-np", "-rh", "Authorization: Bearer header.payload.signature", "-cv", "admin", "-M", "er"},
		},
		{
			name: "cookie",
			request: dto.JWTRequest{
				Token: "header.payload.signature", TargetURL: "https://example.com/me",
				RequestCookie: "token=JWT_HERE", Mode: "er",
			},
			want: []string{"jwt_tool", "header.payload.signature", "-t", "https://example.com/me", "-np", "-rc", "token=header.payload.signature", "-M", "er"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := JWTToolArgs(test.request)
			if err != nil {
				t.Fatalf("build jwt_tool args: %v", err)
			}
			if !reflect.DeepEqual(args, test.want) {
				t.Fatalf("args mismatch\nwant: %v\n got: %v", test.want, args)
			}
		})
	}
}

func TestJWTToolArgsRequiresUnsafeOptInForPlaybookModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"pb", "at"} {
		_, err := JWTToolArgs(dto.JWTRequest{Token: "header.payload.signature", TargetURL: "https://example.com/me", Mode: mode})
		if err == nil {
			t.Fatalf("mode %q was accepted without unsafe opt-in", mode)
		}
	}
}

func TestJWTToolArgsRejectsAdditionalModeOverride(t *testing.T) {
	t.Parallel()

	_, err := JWTToolArgs(dto.JWTRequest{
		Token: "header.payload.signature", TargetURL: "https://example.com/me", AdditionalArgs: "-M at",
	})
	if err == nil {
		t.Fatal("additional_args mode override was accepted")
	}
}

func TestJWTToolArgsAllowsExplicitUnsafePlaybook(t *testing.T) {
	t.Parallel()

	args, err := JWTToolArgs(dto.JWTRequest{
		Token: "header.payload.signature", TargetURL: "https://example.com/me", Mode: "pb", AllowUnsafe: true,
	})
	if err != nil {
		t.Fatalf("JWTToolArgs() error = %v, want nil", err)
	}
	if !reflect.DeepEqual(args, []string{"jwt_tool", "header.payload.signature", "-t", "https://example.com/me", "-np", "-M", "pb"}) {
		t.Fatalf("unexpected explicit playbook args: %v", args)
	}
}
