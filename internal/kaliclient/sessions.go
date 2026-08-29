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

func (c *Client) CreateAuthSession(ctx context.Context, body dto.AuthSessionCreateRequest) (*dto.AuthSessionMetadata, error) {
	var result dto.AuthSessionMetadata
	if err := c.sessionRequest(ctx, http.MethodPost, "/api/sessions", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) ListAuthSessions(ctx context.Context) (*dto.AuthSessionListResult, error) {
	var result dto.AuthSessionListResult
	if err := c.sessionRequest(ctx, http.MethodGet, "/api/sessions", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) DeleteAuthSession(ctx context.Context, sessionID string) error {
	return c.sessionRequest(ctx, http.MethodDelete, "/api/sessions/"+url.PathEscape(sessionID), nil, nil)
}

func (c *Client) sessionRequest(ctx context.Context, method, endpoint string, body, output any) error {
	requestContext, cancel := c.requestContext(ctx, body)
	defer cancel()
	request, err := c.newJSONRequest(requestContext, method, endpoint, body, true)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("authentication session request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		responseBody, _ := io.ReadAll(response.Body)
		return fmt.Errorf("server error %d: %s", response.StatusCode, responseBody)
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		return fmt.Errorf("decode authentication session response: %w", err)
	}
	return nil
}
