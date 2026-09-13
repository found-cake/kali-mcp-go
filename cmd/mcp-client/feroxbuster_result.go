package main

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func parseFeroxbusterDiscoveries(output string) []dto.DiscoveredPath {
	type discoveryKey struct {
		url           string
		statusCode    int
		responseBytes int
	}
	discoveries := make([]dto.DiscoveredPath, 0)
	seen := make(map[discoveryKey]int)
	for line := range strings.Lines(output) {
		var event struct {
			Type          string            `json:"type"`
			URL           string            `json:"url"`
			Status        int               `json:"status"`
			ContentLength int               `json:"content_length"`
			Headers       map[string]string `json:"headers"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &event); err != nil || event.Type != "response" || event.URL == "" || event.Status < 100 || event.Status > 599 {
			continue
		}
		directory := false
		if parsed, err := url.Parse(event.URL); err == nil {
			directory = strings.HasSuffix(parsed.Path, "/")
		}
		if !directory {
			for name, value := range event.Headers {
				if !strings.EqualFold(name, "location") {
					continue
				}
				if parsed, err := url.Parse(value); err == nil {
					directory = strings.HasSuffix(parsed.Path, "/")
				}
				break
			}
		}
		key := discoveryKey{url: event.URL, statusCode: event.Status, responseBytes: event.ContentLength}
		if index, found := seen[key]; found {
			discoveries[index].Directory = discoveries[index].Directory || directory
			continue
		}
		seen[key] = len(discoveries)
		discoveries = append(discoveries, dto.DiscoveredPath{
			URL: event.URL, StatusCode: event.Status, ResponseBytes: event.ContentLength, Directory: directory,
		})
	}
	return discoveries
}
