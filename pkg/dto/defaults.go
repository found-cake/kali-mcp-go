package dto

import "time"

const DefaultTimeoutSeconds = 300

const DefaultTimeout = time.Duration(DefaultTimeoutSeconds) * time.Second
