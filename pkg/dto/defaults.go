package dto

import "time"

const DefaultTimeoutSeconds = 300

const APITokenEnv = "KALI_MCP_API_TOKEN"

const DefaultTimeout = time.Duration(DefaultTimeoutSeconds) * time.Second
