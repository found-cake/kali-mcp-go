package results

import (
	"strings"
	"testing"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestProtectResultRedactsBeforeArtifactStorage(t *testing.T) {
	// Given: command output and metadata containing a caller-designated secret.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	result := &executor.Result{
		Stdout:       "token=private-value\n",
		ArgvRedacted: []string{"-c", "printf private-value"},
		Progress:     &dto.ProgressMetadata{LastObservedOutput: "token=private-value"},
	}
	request := dto.CommandRequest{RedactValues: []string{"private-value"}}

	// When: the result is protected and retained.
	Protect(store, result, request)
	if len(result.Artifacts) != 1 {
		t.Fatalf("expected one artifact: %+v", result.Artifacts)
	}
	if result.Artifacts[0].RedactionState != dto.ArtifactRedacted {
		t.Fatalf("explicit redaction state was not declared: %+v", result.Artifacts[0])
	}
	_, payload, err := store.Read(result.Artifacts[0].ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	// Then: neither inline output nor the artifact contains the secret.
	if strings.Contains(result.Stdout, "private-value") || strings.Contains(result.Progress.LastObservedOutput, "private-value") || strings.Contains(string(payload), "private-value") {
		t.Fatalf("secret remains in protected result: stdout=%q artifact=%s", result.Stdout, payload)
	}
}

func TestProtectReportsArtifactStoreFailure(t *testing.T) {
	// Given: an artifact store whose backing directory has already closed.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close artifact store: %v", err)
	}
	result := &executor.Result{Stdout: "raw evidence"}

	// When: a result is protected for retention.
	Protect(store, result, dto.CommandRequest{})

	// Then: inline evidence remains available and the storage failure is explicit.
	if result.Stdout != "raw evidence" || len(result.Artifacts) != 0 || len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "result artifact unavailable") {
		t.Fatalf("unexpected failed artifact result: %+v", result)
	}
}
