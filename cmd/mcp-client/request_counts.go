package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func attachReportedRequestCount(tool string, result *dto.ToolResult) {
	if tool == "nuclei_scan" {
		if runtime, ok := parseNucleiRuntimeMetadata(result.Stdout + "\n" + result.Stderr); ok {
			result.NucleiRuntime = &runtime
		}
	}
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

func parseFeroxbusterRuntimeStatistics(output string) (errors, initialTargets, connectionErrors int, found bool) {
	maximumRequests := -1
	for line := range strings.Lines(output) {
		var event scannerStatistics
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &event); err != nil || event.Type != "statistics" {
			continue
		}
		requests, ok := parseJSONInteger(event.Requests)
		if ok && requests >= maximumRequests {
			maximumRequests = requests
			errors = parseJSONIntegerOrZero(event.Errors)
			initialTargets = parseJSONIntegerOrZero(event.InitialTargets)
			connectionErrors = parseJSONIntegerOrZero(event.ConnectionErrors)
			found = true
		}
	}
	return errors, initialTargets, connectionErrors, found
}

func parseNucleiRequestCount(output string) (int, bool) {
	return parseStructuredRequestCount(output, func(event scannerStatistics) bool {
		return event.Duration != "" && event.StartedAt != ""
	})
}

type scannerStatistics struct {
	Type             string          `json:"type"`
	Duration         string          `json:"duration"`
	StartedAt        string          `json:"startedAt"`
	Requests         json.RawMessage `json:"requests"`
	Errors           json.RawMessage `json:"errors"`
	Hosts            json.RawMessage `json:"hosts"`
	Matched          json.RawMessage `json:"matched"`
	Percent          json.RawMessage `json:"percent"`
	Templates        json.RawMessage `json:"templates"`
	Total            json.RawMessage `json:"total"`
	InitialTargets   json.RawMessage `json:"initial_targets"`
	ConnectionErrors json.RawMessage `json:"connection_errors"`
}

func parseNucleiRuntimeMetadata(output string) (dto.NucleiRuntimeMetadata, bool) {
	var latest scannerStatistics
	maximumRequests := -1
	for line := range strings.Lines(output) {
		var event scannerStatistics
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &event); err != nil || event.Duration == "" || event.StartedAt == "" {
			continue
		}
		requests, ok := parseJSONInteger(event.Requests)
		if ok && requests >= maximumRequests {
			latest = event
			maximumRequests = requests
		}
	}
	if maximumRequests < 0 {
		return dto.NucleiRuntimeMetadata{}, false
	}
	return dto.NucleiRuntimeMetadata{
		Requests: maximumRequests,
		Errors:   parseJSONIntegerOrZero(latest.Errors), Hosts: parseJSONIntegerOrZero(latest.Hosts),
		Matched: parseJSONIntegerOrZero(latest.Matched), Templates: parseJSONIntegerOrZero(latest.Templates),
		Total: parseJSONIntegerOrZero(latest.Total), Percent: parseJSONFloatOrZero(latest.Percent),
		Duration: latest.Duration, StartedAt: latest.StartedAt,
	}, true
}

func parseJSONIntegerOrZero(raw json.RawMessage) int {
	value, _ := parseJSONInteger(raw)
	return value
}

func parseJSONFloatOrZero(raw json.RawMessage) float64 {
	var value float64
	if err := json.Unmarshal(raw, &value); err == nil && value >= 0 {
		return value
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return 0
	}
	value, _ = strconv.ParseFloat(encoded, 64)
	return value
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
