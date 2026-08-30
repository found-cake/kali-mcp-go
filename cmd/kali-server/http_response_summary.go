package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const maximumHTTPBodyExcerptBytes = 1024

var (
	sensitiveResponsePattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[-_]?key|authorization|cookie)["' ]*[:=]`)
	stackTracePattern        = regexp.MustCompile(`(?im)(traceback \(most recent call last\)|^[[:space:]]+at[[:space:]]+[^[:space:]]+|"stack"[[:space:]]*:|panic:[[:space:]]|system\.[a-z.]*exception)`)
)

type httpResponseSummaryInput struct {
	RetainedBody  []byte
	SafeBody      []byte
	Headers       http.Header
	Secrets       []string
	UTF8          bool
	SensitiveJSON bool
}

func summarizeHTTPResponse(input httpResponseSummaryInput) *dto.HTTPBodySummary {
	digest := sha256.Sum256(input.RetainedBody)
	bodyText := string(input.RetainedBody)
	bodySensitive := input.SensitiveJSON || sensitiveResponsePattern.MatchString(bodyText)
	summary := &dto.HTTPBodySummary{
		BodySHA256:             hex.EncodeToString(digest[:]),
		Location:               tools.RedactURL(input.Headers.Get("Location"), input.Secrets),
		StackTraceSuspected:    stackTracePattern.MatchString(bodyText),
		SensitiveDataSuspected: bodySensitive || input.Headers.Get("Set-Cookie") != "",
	}
	if input.UTF8 {
		if bodySensitive && !input.SensitiveJSON {
			summary.BodyExcerpt = "[REDACTED: sensitive response body]"
		} else {
			excerpt := input.SafeBody
			if len(excerpt) > maximumHTTPBodyExcerptBytes {
				end := maximumHTTPBodyExcerptBytes
				for end > 0 && !utf8.RuneStart(excerpt[end]) {
					end--
				}
				excerpt = excerpt[:end]
				summary.BodyExcerptTruncated = true
			}
			summary.BodyExcerpt = string(excerpt)
		}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(input.SafeBody, &object) == nil {
		for key := range object {
			summary.JSONKeys = append(summary.JSONKeys, key)
		}
		slices.Sort(summary.JSONKeys)
	}
	return summary
}
