package main

import (
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestProtectResultRedactsBeforeArtifactStorage(t *testing.T) {
	// Given: command output and metadata containing a caller-designated secret.
	store, err := newArtifactStore()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.close() })
	result := &executor.Result{
		Stdout:       "token=private-value\n",
		ArgvRedacted: []string{"-c", "printf private-value"},
	}
	request := dto.CommandRequest{RedactValues: []string{"private-value"}}

	// When: the result is protected and retained.
	protectResult(store, result, request)
	if len(result.Artifacts) != 1 {
		t.Fatalf("expected one artifact: %+v", result.Artifacts)
	}
	payload, err := store.read(result.Artifacts[0].ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	// Then: neither inline output nor the artifact contains the secret.
	if strings.Contains(result.Stdout, "private-value") || strings.Contains(string(payload), "private-value") {
		t.Fatalf("secret remains in protected result: stdout=%q artifact=%s", result.Stdout, payload)
	}
}
