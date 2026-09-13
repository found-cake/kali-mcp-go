package kaliclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (c *Client) StartAsync(ctx context.Context, endpoint string, arguments json.RawMessage) (*dto.JobResponse, error) {
	var result dto.JobResponse
	_, err := c.doJSON(ctx, jsonRequestSpec{
		method: http.MethodPost, endpoint: endpoint, body: arguments, authorize: true, checkStatus: true,
		headers:        http.Header{dto.AsyncRequestHeader: []string{"true"}},
		transportError: "start async tool", responseDecodeError: "decode async tool job",
	}, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) JobStatus(ctx context.Context, request dto.JobRequest) (*dto.JobResponse, error) {
	return c.jobOperation(ctx, http.MethodGet, request.JobID, "status")
}

func (c *Client) JobResult(ctx context.Context, request dto.JobRequest) (*dto.JobResponse, error) {
	return c.jobOperation(ctx, http.MethodGet, request.JobID, "result")
}

func (c *Client) JobCancel(ctx context.Context, request dto.JobRequest) (*dto.JobResponse, error) {
	return c.jobOperation(ctx, http.MethodPost, request.JobID, "cancel")
}

func (c *Client) jobOperation(ctx context.Context, method, id, action string) (*dto.JobResponse, error) {
	var result dto.JobResponse
	_, err := c.doJSON(ctx, jsonRequestSpec{
		method: method, endpoint: "/api/jobs/" + url.PathEscape(id) + "/" + action,
		authorize: true, transportError: action + " job", responseDecodeError: "decode job " + action,
	}, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
