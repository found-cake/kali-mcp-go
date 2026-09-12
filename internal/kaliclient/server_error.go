package kaliclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type ServerError struct {
	StatusCode int
	CallID     string
	Body       string
}

func (e *ServerError) Error() string {
	if e.CallID == "" {
		return fmt.Sprintf("server error %d: %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("server error %d (call_id %s): %s", e.StatusCode, e.CallID, e.Body)
}

func (e *ServerError) Details() dto.ErrorResponse {
	var payload dto.ErrorResponse
	if err := json.Unmarshal([]byte(e.Body), &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
		payload.Error = strings.TrimSpace(payload.Error)
		return payload
	}
	if body := strings.TrimSpace(e.Body); body != "" {
		return dto.ErrorResponse{Error: body}
	}
	return dto.ErrorResponse{Error: http.StatusText(e.StatusCode)}
}
