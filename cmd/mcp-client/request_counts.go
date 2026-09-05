package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func attachReportedRequestCount(tool string, result *dto.ToolResult) {
	if result.HTTPRequests != nil {
		return
	}
	output := result.Stdout + "\n" + result.Stderr
	var count int
	var ok bool
	switch tool {
	case "nikto_scan":
		count, ok = parseNiktoRequestCount(output)
	case "feroxbuster_scan":
		count, ok = parseFeroxbusterRequestCount(output)
	case "nuclei_scan":
		count, ok = parseNucleiRequestCount(output)
	}
	if !ok {
		return
	}
	result.HTTPRequests = &count
	result.RequestCountSource = dto.RequestCountParsed
}

func parseFeroxbusterRequestCount(output string) (int, bool) {
	return parseStructuredRequestCount(output, func(event scannerStatistics) bool {
		return event.Type == "statistics"
	})
}

func parseNucleiRequestCount(output string) (int, bool) {
	return parseStructuredRequestCount(output, func(event scannerStatistics) bool {
		return event.Duration != "" && event.StartedAt != ""
	})
}

type scannerStatistics struct {
	Type      string          `json:"type"`
	Duration  string          `json:"duration"`
	StartedAt string          `json:"startedAt"`
	Requests  json.RawMessage `json:"requests"`
}

func parseStructuredRequestCount(output string, matches func(scannerStatistics) bool) (int, bool) {
	maximum := 0
	found := false
	for line := range strings.Lines(output) {
		var event scannerStatistics
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &event); err != nil || !matches(event) {
			continue
		}
		count, ok := parseJSONInteger(event.Requests)
		if ok && (!found || count > maximum) {
			maximum = count
			found = true
		}
	}
	return maximum, found
}

func parseJSONInteger(raw json.RawMessage) (int, bool) {
	var count int
	if err := json.Unmarshal(raw, &count); err == nil && count >= 0 {
		return count, true
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return 0, false
	}
	count, err := strconv.Atoi(encoded)
	return count, err == nil && count >= 0
}

func parseNiktoRequestCount(output string) (int, bool) {
	maximum := 0
	found := false
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)
		for index, field := range fields {
			if strings.TrimSuffix(field, ":") != "requests" || index == 0 {
				continue
			}
			finalSummary := index == 2 && fields[0] == "+"
			progressSummary := index >= 2 && strings.EqualFold(fields[index-2], "completed")
			if !finalSummary && !progressSummary {
				continue
			}
			count, err := strconv.Atoi(fields[index-1])
			if err == nil && count >= maximum {
				maximum = count
				found = true
			}
		}
	}
	return maximum, found
}
