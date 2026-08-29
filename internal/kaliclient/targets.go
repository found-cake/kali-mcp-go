package kaliclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (c *Client) ResolveTarget(ctx context.Context, body dto.ResolveTargetRequest) (*dto.TargetResolutionResult, error) {
	requestContext, cancel := c.requestContext(ctx, body)
	defer cancel()
	request, err := c.newJSONRequest(requestContext, http.MethodPost, "/api/tools/resolve-target", body, true)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		responseBody, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			return nil, fmt.Errorf("read resolver error response: %w", readErr)
		}
		return nil, fmt.Errorf("server error %d: %s", response.StatusCode, responseBody)
	}
	var result dto.TargetResolutionResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode target resolution: %w", err)
	}
	return &result, nil
}
