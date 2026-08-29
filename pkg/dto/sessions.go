package dto

import "time"

type AuthSessionCreateRequest struct {
	Label        string            `json:"label" jsonschema:"human-readable session label, for example customer-session-1"`
	Origin       string            `json:"origin" jsonschema:"exact http or https origin the credentials may be sent to"`
	Headers      map[string]string `json:"headers,omitempty" jsonschema:"sensitive HTTP headers retained only inside kali-server"`
	Cookie       string            `json:"cookie,omitempty" jsonschema:"sensitive Cookie header value retained only inside kali-server"`
	TTLSeconds   int               `json:"ttl_seconds,omitempty" jsonschema:"session lifetime in seconds, maximum 3600"`
	AllowedTools []string          `json:"allowed_tools,omitempty" jsonschema:"optional allowlist of MCP tool binaries"`
}

type AuthSessionDeleteRequest struct {
	SessionID string `json:"session_id" jsonschema:"opaque authentication session handle"`
}

type AuthSessionMetadata struct {
	SessionID    string    `json:"session_id"`
	Label        string    `json:"label"`
	Origin       string    `json:"origin"`
	ExpiresAt    time.Time `json:"expires_at"`
	AllowedTools []string  `json:"allowed_tools"`
	HeaderNames  []string  `json:"header_names"`
	HasCookie    bool      `json:"has_cookie"`
}

type AuthSessionListResult struct {
	Sessions []AuthSessionMetadata `json:"sessions"`
}
