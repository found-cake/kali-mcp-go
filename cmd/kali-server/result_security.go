package main

import (
	"context"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
)

func protectResult(store *artifactStore, result *executor.Result, request any) {
	if result == nil {
		return
	}
	secrets := tools.RequestSecrets(request)
	result.Stdout = tools.RedactText(result.Stdout, secrets)
	result.Stderr = tools.RedactText(result.Stderr, secrets)
	for index := range result.ArgvRedacted {
		result.ArgvRedacted[index] = tools.RedactText(result.ArgvRedacted[index], secrets)
	}
	result.Policy.HealthURL = tools.RedactText(result.Policy.HealthURL, secrets)
	if result.Target != nil {
		result.Target.Original = tools.RedactText(result.Target.Original, secrets)
		result.Target.Selected = tools.RedactText(result.Target.Selected, secrets)
	}
	attachResultArtifact(store, result)
}

func protectStream(ctx context.Context, lines <-chan executor.Line, request any) <-chan executor.Line {
	secrets := tools.RequestSecrets(request)
	if len(secrets) == 0 {
		return lines
	}
	protected := make(chan executor.Line, cap(lines))
	go func() {
		defer close(protected)
		for line := range lines {
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
