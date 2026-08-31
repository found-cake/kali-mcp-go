package main

import (
	"github.com/found-cake/kali-mcp-go/internal/tools"
)

func toolStatus(lookup func(string) bool) map[string]bool {
	runtimeTools := tools.RuntimeToolNames()
	status := make(map[string]bool, len(runtimeTools))
	dirWordlistReady := tools.WordlistExists(tools.DefaultDirWordlistPath())
	johnWordlistReady := tools.WordlistExists(tools.DefaultJohnWordlistPath())

	for _, toolName := range runtimeTools {
		ready := lookup(toolName)
		switch toolName {
		case "gobuster", "dirb":
			ready = ready && dirWordlistReady
		case "john":
			ready = ready && johnWordlistReady
		}
		status[toolName] = ready
	}

	return status
}

func allEssentialToolsAvailable(status map[string]bool) bool {
	for _, toolName := range tools.EssentialRuntimeToolNames() {
		if !status[toolName] {
			return false
		}
	}
	return true
}
