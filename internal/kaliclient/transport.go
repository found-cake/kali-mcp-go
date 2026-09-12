package kaliclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type Client struct {
	base    string
	token   string
	timeout time.Duration
	http    *http.Client
}

const requestTimeoutGrace = 5 * time.Second

type jsonRequestSpec struct {
	method              string
	endpoint            string
	body                any
	authorize           bool
	checkStatus         bool
	requestError        string
	transportError      string
	statusBodyReadError string
	responseDecodeError string
	headers             http.Header
}

func New(baseURL string, timeout time.Duration, token string) *Client {
	if timeout <= 0 {
		timeout = dto.DefaultTimeout
	}
	return &Client{
		base:    strings.TrimRight(baseURL, "/"),
		token:   strings.TrimSpace(token),
		timeout: timeout,
		http:    &http.Client{},
	}
}

func (c *Client) authorize(request *http.Request) {
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) timeoutForBody(body any) time.Duration {
	timeout := c.timeout
	if request, ok := body.(dto.TimeoutRequest); ok {
		if requested := time.Duration(request.GetRequestTimeout()) * time.Second; requested > timeout {
			timeout = requested
		}
	}
	return timeout + requestTimeoutGrace
}

func (c *Client) requestContext(ctx context.Context, body any) (context.Context, context.CancelFunc) {
	timeout := c.timeoutForBody(body)
	if deadline, ok := ctx.Deadline(); ok {
		timeout = boundedRequestTimeout(timeout, time.Until(deadline))
	}
	return context.WithTimeout(ctx, timeout)
}

func boundedRequestTimeout(configured, parentRemaining time.Duration) time.Duration {
	if parentRemaining > requestTimeoutGrace && configured > parentRemaining-requestTimeoutGrace {
		return parentRemaining - requestTimeoutGrace
	}
	return configured
}

func (c *Client) newJSONRequest(ctx context.Context, spec jsonRequestSpec) (*http.Request, error) {
	var reader io.Reader
	if spec.body != nil {
		payload, err := json.Marshal(spec.body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		spec.method,
		c.base+"/"+strings.TrimPrefix(spec.endpoint, "/"),
		reader,
	)
	if err != nil {
		return nil, err
	}
	if spec.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if spec.authorize {
		c.authorize(request)
	}
	for name, values := range spec.headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	return request, nil
}

func (c *Client) doJSON(ctx context.Context, spec jsonRequestSpec, destination any) (string, error) {
	requestContext, cancel := c.requestContext(ctx, spec.body)
	defer cancel()
	request, err := c.newJSONRequest(requestContext, spec)
	if err != nil {
		return "", operationError(spec.requestError, err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return "", operationError(spec.transportError, err)
	}
	defer response.Body.Close()
	if spec.checkStatus && response.StatusCode >= http.StatusBadRequest {
		responseBody, readErr := io.ReadAll(response.Body)
		if readErr != nil && spec.statusBodyReadError != "" {
			return "", operationError(spec.statusBodyReadError, readErr)
		}
		return "", serverResponseError(response, responseBody)
	}
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		return "", operationError(spec.responseDecodeError, err)
	}
	return response.Header.Get(dto.CallIDHeader), nil
}

func operationError(operation string, err error) error {
	if operation == "" {
		return err
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (c *Client) Post(ctx context.Context, endpoint string, body any) (*dto.ToolResult, error) {
	var result dto.ToolResult
	callID, err := c.doJSON(ctx, jsonRequestSpec{
		method: http.MethodPost, endpoint: endpoint, body: body, authorize: true, checkStatus: true,
		transportError: "POST " + endpoint, responseDecodeError: "decode",
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.CallID == "" {
		result.CallID = callID
	}
	return &result, nil
}

func serverResponseError(response *http.Response, body []byte) error {
	return &ServerError{
		StatusCode: response.StatusCode,
		CallID:     response.Header.Get(dto.CallIDHeader),
		Body:       string(body),
	}
}

func (c *Client) Health(ctx context.Context) (*dto.HealthResult, error) {
	var result dto.HealthResult
	callID, err := c.doJSON(ctx, jsonRequestSpec{method: http.MethodGet, endpoint: "/health"}, &result)
	if err != nil {
		return nil, err
	}
	if result.CallID == "" {
		result.CallID = callID
	}
	return &result, nil
}
