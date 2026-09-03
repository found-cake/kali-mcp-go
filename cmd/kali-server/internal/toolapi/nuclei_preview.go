package toolapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const nucleiPreviewTimeout = 30 * time.Second

func previewNucleiTemplates(ctx context.Context, request dto.NucleiRequest) (*dto.NucleiPreviewMetadata, error) {
	args, err := tools.NucleiTemplateListArgs(request)
	if err != nil {
		return nil, err
	}
	result := executor.RunExec(ctx, nucleiPreviewTimeout, args[0], args[1:]...)
	if result.ReturnCode != 0 {
		message := strings.TrimSpace(result.Stderr)
		if message == "" {
			message = strings.TrimSpace(result.Stdout)
		}
		return nil, fmt.Errorf("list Nuclei templates: %s", message)
	}
	preview := tools.SummarizeNucleiTemplateList(request, result.Stdout)
	return &preview, nil
}
