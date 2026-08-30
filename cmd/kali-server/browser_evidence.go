package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

const maximumBrowserScreenshotBytes = 512 * 1024

type browserReport struct {
	RequestedURL         string                `json:"requestedUrl"`
	FinalURL             string                `json:"finalUrl"`
	Status               *int                  `json:"status"`
	Title                string                `json:"title"`
	Dialogs              []browserDialog       `json:"dialogs"`
	Console              []browserConsole      `json:"console"`
	PageErrors           []string              `json:"pageErrors"`
	DOM                  string                `json:"dom,omitempty"`
	DOMTruncated         bool                  `json:"domTruncated,omitempty"`
	DOMBytes             int                   `json:"domBytes,omitempty"`
	DOMArtifactID        string                `json:"domArtifactId,omitempty"`
	NetworkCaptured      bool                  `json:"networkCaptured"`
	Network              []browserNetworkEvent `json:"network,omitempty"`
	NetworkTruncated     bool                  `json:"networkTruncated"`
	NetworkArtifactID    string                `json:"networkArtifactId,omitempty"`
	NetworkEventCount    int                   `json:"networkEventCount,omitempty"`
	ScreenshotCaptured   bool                  `json:"screenshotCaptured,omitempty"`
	ScreenshotMediaType  string                `json:"screenshotMediaType,omitempty"`
	ScreenshotError      string                `json:"screenshotError,omitempty"`
	ScreenshotArtifactID string                `json:"screenshotArtifactId,omitempty"`
}

type browserDialog struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type browserConsole struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type browserNetworkEvent struct {
	Method       string `json:"method"`
	URL          string `json:"url"`
	ResourceType string `json:"resourceType"`
	Status       *int   `json:"status"`
	Failure      string `json:"failure,omitempty"`
}

type browserNetworkEvidence struct {
	Events    []browserNetworkEvent `json:"events"`
	Truncated bool                  `json:"truncated"`
}

func protectBrowserEvidence(store *artifactStore, result *executor.Result, request dto.BrowserRequest) {
	if store == nil || result == nil || (!request.IncludeDOM && !request.CaptureNetwork && !request.CaptureScreenshot) {
		return
	}
	var report browserReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &report); err != nil {
		result.Warnings = append(result.Warnings, "browser evidence extraction unavailable: invalid browser JSON")
		return
	}
	if request.CaptureScreenshot {
		protectBrowserScreenshot(store, result, &report)
	}
	if request.CaptureNetwork && report.NetworkCaptured {
		secrets := tools.RequestSecrets(request)
		for index := range report.Network {
			report.Network[index].URL = tools.RedactText(report.Network[index].URL, secrets)
			report.Network[index].Failure = tools.RedactText(report.Network[index].Failure, secrets)
		}
		protectBrowserNetwork(store, result, &report)
	}
	if request.IncludeDOM {
		store.protectBrowserDOM(result, &report, tools.RequestSecrets(request))
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		result.Warnings = append(result.Warnings, "browser evidence summary unavailable: "+err.Error())
		return
	}
	result.Stdout = string(encoded) + "\n"
	if result.Progress != nil {
		result.Progress.LastObservedOutput = string(encoded)
	}
}

func protectBrowserStreamLine(line executor.Line, request dto.BrowserRequest) executor.Line {
	if line.Stream != "stdout" || (!request.CaptureNetwork && !request.IncludeDOM) {
		return line
	}
	var report browserReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(line.Text)), &report); err != nil {
		return line
	}
	if request.CaptureNetwork {
		report.NetworkEventCount = len(report.Network)
		report.Network = nil
	}
	if request.IncludeDOM {
		report.DOMBytes = len(report.DOM)
		report.DOM = ""
	}
	encoded, err := json.Marshal(report)
	if err == nil {
		line.Text = string(encoded)
	}
	return line
}

func (s *artifactStore) protectBrowserDOM(result *executor.Result, report *browserReport, secrets []string) {
	if report.DOM == "" {
		result.Warnings = append(result.Warnings, "browser DOM was requested but not captured")
		return
	}
	redactedDOM := tools.RedactText(report.DOM, secrets)
	reference, err := s.saveContent(artifactContent{
		Kind: "browser-dom-html", MediaType: fiber.MIMETextHTML, Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactRedacted, SourceCallID: result.CallID,
		Relation: dto.ArtifactRelationBrowserDOM, Payload: []byte(redactedDOM),
	}, time.Now().UTC())
	if err != nil {
		result.Warnings = append(result.Warnings, "browser DOM artifact unavailable: "+err.Error())
		return
	}
	result.Artifacts = append(result.Artifacts, reference)
	report.DOMBytes = len(report.DOM)
	report.DOMArtifactID = reference.ID
	report.DOM = ""
}

func protectBrowserScreenshot(store *artifactStore, result *executor.Result, report *browserReport) {
	if !report.ScreenshotCaptured || result.BrowserScreenshotPath == "" {
		warning := "browser screenshot was requested but not captured"
		if report.ScreenshotError != "" {
			warning += ": " + report.ScreenshotError
		}
		result.Warnings = append(result.Warnings, warning)
		return
	}
	payload, err := os.ReadFile(result.BrowserScreenshotPath)
	if err != nil || len(payload) > maximumBrowserScreenshotBytes {
		result.Warnings = append(result.Warnings, "browser screenshot artifact unavailable")
		return
	}
	mediaType := report.ScreenshotMediaType
	if mediaType == "" {
		mediaType = "image/png"
	}
	reference, err := store.saveContent(artifactContent{
		Kind: "browser-screenshot", MediaType: mediaType, Encoding: dto.ArtifactEncodingBase64,
		RedactionState: dto.ArtifactSensitiveUnredacted, SourceCallID: result.CallID,
		Relation: dto.ArtifactRelationBrowserScreenshot, Payload: payload,
	}, time.Now().UTC())
	if err != nil {
		result.Warnings = append(result.Warnings, "browser screenshot artifact unavailable: "+err.Error())
		return
	}
	result.Artifacts = append(result.Artifacts, reference)
	report.ScreenshotArtifactID = reference.ID
}

func protectBrowserNetwork(store *artifactStore, result *executor.Result, report *browserReport) {
	report.NetworkEventCount = len(report.Network)
	payload, err := json.Marshal(browserNetworkEvidence{Events: report.Network, Truncated: report.NetworkTruncated})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("browser network artifact unavailable: %v", err))
		return
	}
	reference, err := store.saveContent(artifactContent{
		Kind: "browser-network-json", MediaType: fiber.MIMEApplicationJSON, Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactRedacted, SourceCallID: result.CallID,
		Relation: dto.ArtifactRelationBrowserNetwork, Payload: payload,
	}, time.Now().UTC())
	if err != nil {
		result.Warnings = append(result.Warnings, "browser network artifact unavailable: "+err.Error())
		return
	}
	result.Artifacts = append(result.Artifacts, reference)
	report.NetworkArtifactID = reference.ID
	report.Network = nil
}
