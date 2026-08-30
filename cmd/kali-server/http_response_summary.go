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
	Body    []byte
	Headers http.Header
	Secrets []string
	UTF8    bool
}

func summarizeHTTPResponse(input httpResponseSummaryInput) *dto.HTTPBodySummary {
	digest := sha256.Sum256(input.Body)
	bodyText := string(input.Body)
	bodySensitive := sensitiveResponsePattern.MatchString(bodyText)
	summary := &dto.HTTPBodySummary{
		BodySHA256:             hex.EncodeToString(digest[:]),
		Location:               tools.RedactURL(input.Headers.Get("Location"), input.Secrets),
		StackTraceSuspected:    stackTracePattern.MatchString(bodyText),
		SensitiveDataSuspected: bodySensitive || input.Headers.Get("Set-Cookie") != "",
	}
	if input.UTF8 {
		excerpt := input.Body
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
	var object map[string]json.RawMessage
	if json.Unmarshal(input.Body, &object) == nil {
		for key := range object {
			summary.JSONKeys = append(summary.JSONKeys, key)
		}
		slices.Sort(summary.JSONKeys)
	}
	return summary
}
