package kaliclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (c *Client) ReadArtifact(ctx context.Context, body dto.ArtifactReadRequest) (*dto.ArtifactReadResult, error) {
	requestContext, cancel := c.requestContext(ctx, nil)
	defer cancel()
	query := url.Values{}
	query.Set("offset", strconv.FormatInt(body.Offset, 10))
	query.Set("limit", strconv.Itoa(body.Limit))
	endpoint := "/api/artifacts/" + url.PathEscape(body.ArtifactID) + "/page?" + query.Encode()
	request, err := c.newJSONRequest(requestContext, http.MethodGet, endpoint, nil, true)
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
	var result dto.ArtifactReadResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode artifact response: %w", err)
	}
	return &result, nil
}
