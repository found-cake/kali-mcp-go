package kaliclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func (c *Client) ScanCapabilities(ctx context.Context) (*dto.ScanCapabilitiesResult, error) {
	var result dto.ScanCapabilitiesResult
	callID, err := c.doJSON(ctx, jsonRequestSpec{
		method: http.MethodGet, endpoint: "/api/tools/capabilities", authorize: true, checkStatus: true,
		transportError: "get scan capabilities", responseDecodeError: "decode scan capabilities",
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.CallID == "" {
		result.CallID = callID
	}
	return &result, nil
}

func (c *Client) ResolveTarget(ctx context.Context, body dto.ResolveTargetRequest) (*dto.TargetResolutionResult, error) {
	var result dto.TargetResolutionResult
	callID, err := c.doJSON(ctx, jsonRequestSpec{
		method: http.MethodPost, endpoint: "/api/tools/resolve-target", body: body, authorize: true, checkStatus: true,
		transportError: "resolve target", statusBodyReadError: "read resolver error response",
		responseDecodeError: "decode target resolution",
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.CallID == "" {
		result.CallID = callID
	}
	return &result, nil
}

func (c *Client) ReadArtifact(ctx context.Context, body dto.ArtifactReadRequest) (*dto.ArtifactReadResult, error) {
	query := url.Values{}
	query.Set("offset", strconv.FormatInt(body.Offset, 10))
	query.Set("limit", strconv.Itoa(body.Limit))
	endpoint := "/api/artifacts/" + url.PathEscape(body.ArtifactID) + "/page?" + query.Encode()
	var result dto.ArtifactReadResult
	callID, err := c.doJSON(ctx, jsonRequestSpec{
		method: http.MethodGet, endpoint: endpoint, authorize: true, checkStatus: true,
		requestError: "create artifact request", transportError: "read artifact",
		responseDecodeError: "decode artifact response",
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.CallID == "" {
		result.CallID = callID
	}
	return &result, nil
}
