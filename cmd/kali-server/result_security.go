package main

import (
	"context"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func protectResult(store *artifactStore, result *executor.Result, request any) {
	if result == nil {
		return
	}
	secrets := tools.RequestSecrets(request)
	if browserRequest, ok := request.(dto.BrowserRequest); ok {
		protectBrowserEvidence(store, result, browserRequest)
	}
	result.Stdout = tools.RedactText(result.Stdout, secrets)
	result.Stderr = tools.RedactText(result.Stderr, secrets)
	if result.Progress != nil {
		result.Progress.LastObservedOutput = tools.RedactText(result.Progress.LastObservedOutput, secrets)
	}
	for index := range result.ArgvRedacted {
		result.ArgvRedacted[index] = tools.RedactText(result.ArgvRedacted[index], secrets)
	}
	result.Policy.HealthURL = tools.RedactText(result.Policy.HealthURL, secrets)
	if result.Target != nil {
		result.Target.Original = tools.RedactText(result.Target.Original, secrets)
		result.Target.Selected = tools.RedactText(result.Target.Selected, secrets)
	}
	if result.HTTPRequest != nil {
		result.HTTPRequest.Headers = tools.RedactHeaders(result.HTTPRequest.Headers, secrets)
		result.HTTPRequest.URL = tools.RedactURL(result.HTTPRequest.URL, secrets)
		result.HTTPRequest.Host = tools.RedactText(result.HTTPRequest.Host, secrets)
	}
	if result.HTTPResponse != nil {
		result.HTTPResponse.Headers = tools.RedactHeaders(result.HTTPResponse.Headers, secrets)
		result.HTTPResponse.FinalURL = tools.RedactURL(result.HTTPResponse.FinalURL, secrets)
		if result.HTTPResponse.Summary != nil {
			result.HTTPResponse.Summary.Location = tools.RedactURL(result.HTTPResponse.Summary.Location, secrets)
			result.HTTPResponse.Summary.BodyExcerpt = tools.RedactText(result.HTTPResponse.Summary.BodyExcerpt, secrets)
		}
	}
	if result.SQLMapAnalysis != nil {
		for index := range result.SQLMapAnalysis.Parameters {
			result.SQLMapAnalysis.Parameters[index].Name = tools.RedactText(result.SQLMapAnalysis.Parameters[index].Name, secrets)
		}
	}
	attachResultArtifact(store, result)
}

func protectStream(ctx context.Context, lines <-chan executor.Line, request any) <-chan executor.Line {
	secrets := tools.RequestSecrets(request)
	browserRequest, protectBrowser := request.(dto.BrowserRequest)
	if len(secrets) == 0 && (!protectBrowser || !browserRequest.CaptureNetwork) {
		return lines
	}
	protected := make(chan executor.Line, cap(lines))
	go func() {
		defer close(protected)
		for line := range lines {
			if protectBrowser {
				line = protectBrowserStreamLine(line, browserRequest)
			}
			line.Text = tools.RedactText(line.Text, secrets)
			select {
			case protected <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	return protected
}
