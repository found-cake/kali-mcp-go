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
			want: []string{"jwt_tool", "header.payload.signature", "-t", "https://example.com/me", "-np", "-rh", "Authorization: Bearer header.payload.signature", "-cv", "admin", "-M", "at"},
		},
		{
			name: "cookie",
			request: dto.JWTRequest{
				Token: "header.payload.signature", TargetURL: "https://example.com/me",
				RequestCookie: "token=JWT_HERE", Mode: "pb",
			},
			want: []string{"jwt_tool", "header.payload.signature", "-t", "https://example.com/me", "-np", "-rc", "token=header.payload.signature", "-M", "pb"},
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
