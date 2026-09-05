package kaliclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

func (e *ServerError) Message() string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(e.Body), &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
		return strings.TrimSpace(payload.Error)
	}
	if body := strings.TrimSpace(e.Body); body != "" {
		return body
	}
	return http.StatusText(e.StatusCode)
}
