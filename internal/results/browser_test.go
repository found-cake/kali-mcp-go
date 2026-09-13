package results

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestProtectResultExtractsOptInBrowserEvidenceArtifacts(t *testing.T) {
	// Given: browser output containing bounded network evidence and an encoded screenshot.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}
	screenshotPath := t.TempDir() + "/screenshot.png"
	if err := os.WriteFile(screenshotPath, png, 0o600); err != nil {
		t.Fatalf("write screenshot fixture: %v", err)
	}
	result := &executor.Result{
		CallID: "call-browser", Tool: "browser-check", ReturnCode: 0,
		BrowserScreenshotPath: screenshotPath,
		Stdout:                `{"requestedUrl":"http://example.test/","finalUrl":"http://example.test/","navigationResponseReceived":true,"navigationStatus":200,"navigationResponseUrl":"http://example.test/","title":"Example","dialogs":[],"console":[],"pageErrors":[],"dom":"<html>private-value</html>","networkCaptured":true,"network":[{"method":"GET","url":"http://example.test/api?token=private-value","resourceType":"xhr","status":200}],"screenshotCaptured":true,"screenshotMediaType":"image/png"}`,
		Progress:              &dto.ProgressMetadata{LastObservedOutput: `{"network":[{"url":"http://example.test/api?token=private-value"}]}`},
	}
	request := dto.BrowserRequest{
		ScanOptions: dto.ScanOptions{RedactValues: []string{"private-value"}},
		IncludeDOM:  true, CaptureNetwork: true, CaptureScreenshot: true,
	}

	// When: the result is protected before inline delivery and retention.
	Protect(store, result, request)

	// Then: large and sensitive evidence is linked separately from the redacted JSON result.
	if len(result.Artifacts) != 4 || strings.Contains(result.Stdout, base64.StdEncoding.EncodeToString(png)) || strings.Contains(result.Stdout, "private-value") || strings.Contains(result.Progress.LastObservedOutput, "private-value") {
		t.Fatalf("browser evidence was not extracted safely: result=%+v", result)
	}
	screenshot := artifactByRelation(t, result.Artifacts, dto.ArtifactRelationBrowserScreenshot)
	reference, payload, err := store.Read(screenshot.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("read screenshot: %v", err)
	}
	if string(payload) != string(png) || reference.Encoding != dto.ArtifactEncodingBase64 || reference.RedactionState != dto.ArtifactSensitiveUnredacted {
		t.Fatalf("unexpected screenshot artifact: %+v", reference)
	}
	page, err := store.ReadPage(dto.ArtifactReadRequest{ArtifactID: screenshot.ID, Limit: 256}, time.Now().UTC())
	if err != nil || page.Content != base64.StdEncoding.EncodeToString(png) || page.Encoding != dto.ArtifactEncodingBase64 {
		t.Fatalf("unexpected screenshot page: err=%v page=%+v", err, page)
	}
	network := artifactByRelation(t, result.Artifacts, dto.ArtifactRelationBrowserNetwork)
	_, payload, err = store.Read(network.ID, time.Now().UTC())
	if err != nil || strings.Contains(string(payload), "private-value") || network.RedactionState != dto.ArtifactRedacted {
		t.Fatalf("network artifact was not redacted: err=%v payload=%s", err, payload)
	}
	dom := artifactByRelation(t, result.Artifacts, dto.ArtifactRelationBrowserDOM)
	_, payload, err = store.Read(dom.ID, time.Now().UTC())
	if err != nil || strings.Contains(string(payload), "private-value") || !strings.Contains(string(payload), "[REDACTED]") || dom.RedactionState != dto.ArtifactRedacted || dom.MediaType != "text/html" || network.MediaType != "application/json" {
		t.Fatalf("DOM artifact was not redacted: err=%v payload=%s", err, payload)
	}
	if result.Evidence == nil || result.Evidence.GroupID != result.CallID || len(result.Evidence.Artifacts) != 4 || result.Evidence.PrimaryArtifactID == "" {
		t.Fatalf("browser evidence manifest is incomplete: %+v", result.Evidence)
	}
}

func TestProtectResultPreservesBrowserEvidenceTruncationFlags(t *testing.T) {
	// Given: browser output whose bounded evidence collectors reached their limits.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close artifact store: %v", err)
		}
	})
	result := &executor.Result{
		CallID: "call-browser-bounded", Tool: "browser-check", ReturnCode: 0,
		Stdout: `{"requestedUrl":"http://example.test/","finalUrl":"http://example.test/","navigationResponseReceived":true,"navigationStatus":200,"navigationResponseUrl":"http://example.test/","title":"Example","dialogs":[],"dialogsTruncated":true,"console":[],"consoleTruncated":true,"pageErrors":[],"pageErrorsTruncated":true,"networkCaptured":true,"network":[]}`,
	}

	// When: browser evidence is normalized for the MCP response.
	protectBrowserEvidence(store, result, dto.BrowserRequest{CaptureNetwork: true})
	var report browserReport
	if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
		t.Fatalf("decode protected browser report: %v", err)
	}

	// Then: callers can distinguish complete empty collections from truncated ones.
	if !report.DialogsTruncated || !report.ConsoleTruncated || !report.PageErrorsTruncated {
		t.Fatalf("browser truncation metadata was dropped: %+v", report)
	}
}

func TestProtectResultPreservesBrowserNavigationEvidence(t *testing.T) {
	// Given: browser output with an explicit main-document navigation response.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	result := &executor.Result{
		CallID: "call-browser-navigation", Tool: "browser-check", ReturnCode: 0,
		Stdout: `{"requestedUrl":"http://example.test/#/route","finalUrl":"http://example.test/#/route","navigationResponseReceived":true,"navigationStatus":200,"navigationResponseUrl":"http://example.test/","dialogs":[],"console":[],"pageErrors":[],"networkCaptured":true,"network":[]}`,
	}

	// When: browser evidence is normalized for the MCP response.
	protectBrowserEvidence(store, result, dto.BrowserRequest{CaptureNetwork: true})
	var report browserReport
	if err := json.Unmarshal([]byte(result.Stdout), &report); err != nil {
		t.Fatalf("decode protected browser report: %v", err)
	}

	// Then: the main-document response remains distinct from the final SPA URL.
	if !report.NavigationResponseReceived || report.NavigationStatus == nil || *report.NavigationStatus != 200 || report.NavigationResponseURL == nil || *report.NavigationResponseURL != "http://example.test/" {
		t.Fatalf("browser navigation evidence was dropped: %+v", report)
	}
}

func TestProtectReportsInvalidBrowserJSON(t *testing.T) {
	// Given: browser evidence capture was requested but stdout is not valid browser JSON.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	result := &executor.Result{Stdout: "not-json"}

	// When: the browser result crosses the evidence boundary.
	Protect(store, result, dto.BrowserRequest{IncludeDOM: true})

	// Then: the result remains usable and carries the established extraction warning.
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "invalid browser JSON") || result.Stdout != "not-json" {
		t.Fatalf("unexpected invalid browser result: %+v", result)
	}
}

func TestProtectResultPreservesBrowserEvidenceByDefault(t *testing.T) {
	// Given: browser evidence containing a credential-like URL and DOM value.
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create artifact store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	result := &executor.Result{
		CallID: "call-browser-raw", Tool: "browser-check", ReturnCode: 0,
		Stdout: `{"requestedUrl":"http://example.test/","finalUrl":"http://example.test/","navigationResponseReceived":true,"navigationStatus":200,"navigationResponseUrl":"http://example.test/","dialogs":[],"console":[],"pageErrors":[],"dom":"<html>server-secret</html>","networkCaptured":true,"network":[{"method":"GET","url":"http://example.test/api?token=server-secret","resourceType":"xhr","status":200}]}`,
	}
	request := dto.BrowserRequest{IncludeDOM: true, CaptureNetwork: true}

	// When: the final result and related evidence are retained without redaction values.
	Protect(store, result, request)

	// Then: raw DOM and network values remain and their artifact state declares that fact.
	for _, relation := range []dto.ArtifactRelation{dto.ArtifactRelationBrowserDOM, dto.ArtifactRelationBrowserNetwork} {
		artifact := artifactByRelation(t, result.Artifacts, relation)
		_, payload, readErr := store.Read(artifact.ID, time.Now().UTC())
		if readErr != nil || !strings.Contains(string(payload), "server-secret") || artifact.RedactionState != dto.ArtifactSensitiveUnredacted {
			t.Fatalf("raw browser artifact was not preserved: relation=%s err=%v payload=%s ref=%+v", relation, readErr, payload, artifact)
		}
	}
}

func TestProtectBrowserStreamLineOmitsNetworkDetails(t *testing.T) {
	// Given: an opt-in browser stream result carrying captured network events.
	line := executor.Line{Stream: "stdout", Text: `{"dom":"<html>private</html>","networkCaptured":true,"network":[{"method":"GET","url":"http://example.test/private","resourceType":"xhr","status":200}]}`}

	// When: the SSE line is protected before delivery.
	protected := protectBrowserStreamLine(line, dto.BrowserRequest{IncludeDOM: true, CaptureNetwork: true})

	// Then: only the event count remains inline; details are reserved for the artifact.
	if strings.Contains(protected.Text, "/private") || strings.Contains(protected.Text, "<html>") || !strings.Contains(protected.Text, `"networkEventCount":1`) || !strings.Contains(protected.Text, `"domBytes":20`) {
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
