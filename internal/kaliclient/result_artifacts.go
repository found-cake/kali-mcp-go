package kaliclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (c *Client) ReadArtifact(ctx context.Context, artifactID string) (*dto.ArtifactReadResult, error) {
	requestContext, cancel := c.requestContext(ctx, nil)
	defer cancel()
	request, err := c.newJSONRequest(requestContext, http.MethodGet, "/api/artifacts/"+url.PathEscape(artifactID), nil, true)
	if err != nil {
		return nil, fmt.Errorf("create artifact request: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		responseBody, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("server error %d: %s", response.StatusCode, responseBody)
	}
	var content json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&content); err != nil {
		return nil, fmt.Errorf("decode artifact response: %w", err)
	}
	return &dto.ArtifactReadResult{ArtifactID: artifactID, Content: string(content)}, nil
}
