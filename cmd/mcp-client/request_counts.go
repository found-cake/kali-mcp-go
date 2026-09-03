package main

import (
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func attachReportedRequestCount(tool string, result *dto.ToolResult) {
	if tool != "nikto_scan" || result.HTTPRequests != nil {
		return
	}
	count, ok := parseNiktoRequestCount(result.Stdout + "\n" + result.Stderr)
	if !ok {
		return
	}
	result.HTTPRequests = &count
	result.RequestCountSource = dto.RequestCountParsed
}

func parseNiktoRequestCount(output string) (int, bool) {
	maximum := 0
	found := false
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field != "requests:" || index == 0 {
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
