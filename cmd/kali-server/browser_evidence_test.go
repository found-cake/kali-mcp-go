package main

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestProtectResultExtractsOptInBrowserEvidenceArtifacts(t *testing.T) {
	// Given: browser output containing bounded network evidence and an encoded screenshot.
	store, err := newArtifactStore()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.close() })
	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}
	screenshotPath := t.TempDir() + "/screenshot.png"
	if err := os.WriteFile(screenshotPath, png, 0o600); err != nil {
		t.Fatalf("write screenshot fixture: %v", err)
	}
	result := &executor.Result{
		CallID: "call-browser", Tool: "browser-check", ReturnCode: 0,
		BrowserScreenshotPath: screenshotPath,
		Stdout:                `{"requestedUrl":"http://example.test/","finalUrl":"http://example.test/","status":200,"title":"Example","dialogs":[],"console":[],"pageErrors":[],"networkCaptured":true,"network":[{"method":"GET","url":"http://example.test/api?token=private-value","resourceType":"xhr","status":200}],"screenshotCaptured":true,"screenshotMediaType":"image/png"}`,
		Progress:              &dto.ProgressMetadata{LastObservedOutput: `{"network":[{"url":"http://example.test/api?token=private-value"}]}`},
	}
	request := dto.BrowserRequest{
		ScanOptions:    dto.ScanOptions{RedactValues: []string{"private-value"}},
		CaptureNetwork: true, CaptureScreenshot: true,
	}

	// When: the result is protected before inline delivery and retention.
	protectResult(store, result, request)

	// Then: large and sensitive evidence is linked separately from the redacted JSON result.
	if len(result.Artifacts) != 3 || strings.Contains(result.Stdout, base64.StdEncoding.EncodeToString(png)) || strings.Contains(result.Stdout, "private-value") || strings.Contains(result.Progress.LastObservedOutput, "private-value") {
		t.Fatalf("browser evidence was not extracted safely: result=%+v", result)
	}
	screenshot := artifactByRelation(t, result.Artifacts, dto.ArtifactRelationBrowserScreenshot)
	stored, payload, err := store.read(screenshot.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("read screenshot: %v", err)
	}
	if string(payload) != string(png) || stored.reference.Encoding != dto.ArtifactEncodingBase64 || stored.reference.RedactionState != dto.ArtifactSensitiveUnredacted {
		t.Fatalf("unexpected screenshot artifact: %+v", stored.reference)
	}
	page, err := store.readPage(dto.ArtifactReadRequest{ArtifactID: screenshot.ID, Limit: 256}, time.Now().UTC())
	if err != nil || page.Content != base64.StdEncoding.EncodeToString(png) || page.Encoding != dto.ArtifactEncodingBase64 {
		t.Fatalf("unexpected screenshot page: err=%v page=%+v", err, page)
	}
	network := artifactByRelation(t, result.Artifacts, dto.ArtifactRelationBrowserNetwork)
	_, payload, err = store.read(network.ID, time.Now().UTC())
	if err != nil || strings.Contains(string(payload), "private-value") {
		t.Fatalf("network artifact was not redacted: err=%v payload=%s", err, payload)
	}
}

func TestProtectBrowserStreamLineOmitsNetworkDetails(t *testing.T) {
	// Given: an opt-in browser stream result carrying captured network events.
	line := executor.Line{Stream: "stdout", Text: `{"networkCaptured":true,"network":[{"method":"GET","url":"http://example.test/private","resourceType":"xhr","status":200}]}`}

	// When: the SSE line is protected before delivery.
	protected := protectBrowserStreamLine(line, dto.BrowserRequest{CaptureNetwork: true})

	// Then: only the event count remains inline; details are reserved for the artifact.
	if strings.Contains(protected.Text, "/private") || !strings.Contains(protected.Text, `"networkEventCount":1`) {
		t.Fatalf("unexpected protected browser stream: %s", protected.Text)
	}
}

func artifactByRelation(t *testing.T, artifacts []dto.ArtifactRef, relation dto.ArtifactRelation) dto.ArtifactRef {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Relation == relation {
			return artifact
		}
	}
	t.Fatalf("artifact relation not found: %s", relation)
	return dto.ArtifactRef{}
}
