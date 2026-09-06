package main

import (
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func parseDirbDiscoveries(output string) []dto.DiscoveredPath {
	discoveries := make([]dto.DiscoveredPath, 0)
	for line := range strings.Lines(strings.ReplaceAll(output, "\r", "\n")) {
		trimmed := strings.TrimSpace(line)
		if directory, found := strings.CutPrefix(trimmed, "==> DIRECTORY:"); found {
			discoveries = append(discoveries, dto.DiscoveredPath{URL: strings.TrimSpace(directory), Directory: true})
			continue
		}
		content, found := strings.CutPrefix(trimmed, "+ ")
		if !found {
			continue
		}
		address, metrics, found := strings.Cut(content, " (CODE:")
		if !found {
			continue
		}
		status, size, found := strings.Cut(strings.TrimSuffix(metrics, ")"), "|SIZE:")
		if !found {
			continue
		}
		statusCode, statusErr := strconv.Atoi(status)
		responseBytes, sizeErr := strconv.Atoi(size)
		if statusErr != nil || sizeErr != nil {
			continue
		}
		discoveries = append(discoveries, dto.DiscoveredPath{
			URL: strings.TrimSpace(address), StatusCode: statusCode, ResponseBytes: responseBytes,
		})
	}
	return discoveries
}
