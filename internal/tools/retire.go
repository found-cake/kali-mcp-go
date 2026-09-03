package tools

import (
	"context"
	"fmt"
	"os"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type RetirePlan struct {
	args    []string
	tempDir string
}

func PrepareRetire(ctx context.Context, request dto.RetireRequest) (*RetirePlan, error) {
	provided := 0
	for _, selected := range []bool{request.Path != "", request.URL != "", len(request.ScriptURLs) > 0} {
		if selected {
			provided++
		}
	}
	if provided != 1 {
		return nil, fmt.Errorf("provide exactly one of path, url, or script_urls")
	}
	if request.Path != "" {
		args, err := RetireArgs(request)
		if err != nil {
			return nil, err
		}
		return &RetirePlan{args: args}, nil
	}
	tempDir, err := os.MkdirTemp("", "kali-mcp-retire-*")
	if err != nil {
		return nil, fmt.Errorf("create retire workspace: %w", err)
	}
	plan := &RetirePlan{tempDir: tempDir}
	var downloadErr error
	if request.URL != "" {
		downloadErr = downloadPageScripts(ctx, request.URL, tempDir)
	} else {
		downloadErr = downloadExplicitScripts(ctx, request.ScriptURLs, tempDir)
	}
	if downloadErr != nil {
		plan.Cleanup()
		return nil, downloadErr
	}
	request.Path = tempDir
	request.URL = ""
	request.ScriptURLs = nil
	plan.args, err = RetireArgs(request)
	if err != nil {
		plan.Cleanup()
		return nil, err
	}
	return plan, nil
}

func (p *RetirePlan) Args() []string {
	return append([]string(nil), p.args...)
}

func (p *RetirePlan) EphemeralPath() string {
	return p.tempDir
}

func (p *RetirePlan) Cleanup() {
	if p != nil && p.tempDir != "" {
		_ = os.RemoveAll(p.tempDir)
	}
}
