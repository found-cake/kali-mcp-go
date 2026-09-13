package results

import (
	"context"
	"strings"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func HideImplementationPaths(result *executor.Result, paths ...string) {
	if result == nil {
		return
	}
	for index, argument := range result.ArgvRedacted {
		for _, path := range paths {
			if path != "" {
				argument = strings.ReplaceAll(argument, path, "[EPHEMERAL_PATH]")
			}
		}
		result.ArgvRedacted[index] = argument
	}
}

func Protect(store *artifactstore.Store, result *executor.Result, request any) {
	if result == nil {
		return
	}
	secrets := tools.RequestSecrets(request)
	redactor := tools.NewRedactor(secrets)
	if browserRequest, ok := request.(dto.BrowserRequest); ok {
		protectBrowserEvidence(store, result, browserRequest)
	}
	result.Stdout = redactor.Text(result.Stdout)
	result.Stderr = redactor.Text(result.Stderr)
	if result.Progress != nil {
		result.Progress.LastObservedOutput = redactor.Text(result.Progress.LastObservedOutput)
	}
	for index := range result.ArgvRedacted {
		result.ArgvRedacted[index] = redactor.Text(result.ArgvRedacted[index])
	}
	result.Policy.HealthURL = redactor.Text(result.Policy.HealthURL)
	if result.Target != nil {
		result.Target.Original = redactor.Text(result.Target.Original)
		result.Target.Selected = redactor.Text(result.Target.Selected)
	}
	if result.HTTPRequest != nil {
		result.HTTPRequest.Headers = redactor.Headers(result.HTTPRequest.Headers)
		result.HTTPRequest.URL = redactor.Text(result.HTTPRequest.URL)
		result.HTTPRequest.Host = redactor.Text(result.HTTPRequest.Host)
	}
	if result.HTTPResponse != nil {
		result.HTTPResponse.Headers = redactor.Headers(result.HTTPResponse.Headers)
		result.HTTPResponse.FinalURL = redactor.Text(result.HTTPResponse.FinalURL)
		if result.HTTPResponse.Summary != nil {
			result.HTTPResponse.Summary.Location = redactor.Text(result.HTTPResponse.Summary.Location)
			result.HTTPResponse.Summary.BodyExcerpt = redactor.Text(result.HTTPResponse.Summary.BodyExcerpt)
		}
	}
	if result.SQLMapAnalysis != nil {
		for index := range result.SQLMapAnalysis.Parameters {
			result.SQLMapAnalysis.Parameters[index].Name = redactor.Text(result.SQLMapAnalysis.Parameters[index].Name)
		}
	}
	attachResultArtifact(store, result, artifactRedactionState(secrets))
}

func artifactRedactionState(values []string) dto.ArtifactRedactionState {
	if len(values) == 0 {
		return dto.ArtifactSensitiveUnredacted
	}
	return dto.ArtifactRedacted
}

func ProtectStream(ctx context.Context, lines <-chan executor.Line, request any) <-chan executor.Line {
	secrets := tools.RequestSecrets(request)
	browserRequest, protectBrowser := request.(dto.BrowserRequest)
	if len(secrets) == 0 && (!protectBrowser || (!browserRequest.CaptureNetwork && !browserRequest.IncludeDOM)) {
		return lines
	}
	redactor := tools.NewRedactor(secrets)
	protected := make(chan executor.Line, cap(lines))
	go func() {
		defer close(protected)
		for line := range lines {
			if protectBrowser {
				line = protectBrowserStreamLine(line, browserRequest)
			}
			line.Text = redactor.Text(line.Text)
			select {
			case protected <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	return protected
}
