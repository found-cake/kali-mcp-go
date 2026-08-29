package kaliclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (c *Client) ScanCapabilities(ctx context.Context) (*dto.ScanCapabilitiesResult, error) {
	requestContext, cancel := c.requestContext(ctx, struct{}{})
	defer cancel()
	request, err := c.newJSONRequest(requestContext, http.MethodGet, "/api/tools/capabilities", nil, true)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("get scan capabilities: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		responseBody, _ := io.ReadAll(response.Body)
		return nil, serverResponseError(response, responseBody)
	}
	var result dto.ScanCapabilitiesResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode scan capabilities: %w", err)
	}
	if result.CallID == "" {
		result.CallID = response.Header.Get(dto.CallIDHeader)
	}
	return &result, nil
}
