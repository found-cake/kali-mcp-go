package results

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestProtectConcurrentRequestsKeepSeparateSecretsAndArtifacts(t *testing.T) {
	store, err := artifacts.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	values := make([]string, 32)
	for index := range values {
		values[index] = fmt.Sprintf("private-%02d", index)
	}
	content := strings.Join(values, " ")
	headers := http.Header{"X-Values": {content}}
	for caller, secret := range values {
		t.Run(fmt.Sprint(caller), func(t *testing.T) {
			t.Parallel()
			callID := fmt.Sprintf("call-fixture-%02d", caller)
			result := &executor.Result{CallID: callID, Stdout: content, HTTPRequest: &dto.HTTPRequestMetadata{Headers: headers}}
			Protect(store, result, dto.CommandRequest{RedactValues: []string{secret}})
			want := strings.ReplaceAll(content, secret, "[REDACTED]")
			if result.Stdout != want || result.HTTPRequest.Headers.Get("X-Values") != want || headers.Get("X-Values") != content {
				t.Fatal("request redaction or shared headers changed")
			}
			if len(result.Artifacts) != 1 {
				t.Fatalf("artifact count=%d", len(result.Artifacts))
			}
			reference, payload, err := store.Read(result.Artifacts[0].ID, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			var saved dto.ToolResult
			if err := json.Unmarshal(payload, &saved); err != nil {
				t.Fatal(err)
			}
			if reference.SourceCallID != callID || saved.CallID != callID || saved.Stdout != want || saved.HTTPRequest.Headers.Get("X-Values") != want {
				t.Fatal("stored artifact mixed request state")
			}
		})
	}
}
