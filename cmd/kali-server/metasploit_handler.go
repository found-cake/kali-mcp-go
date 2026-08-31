package main

import (
	"fmt"
	"os"
	"strings"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func handleMetasploit(c fiber.Ctx) error {
	request, err := httpapi.ParseRequest(c, validateMetasploitRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	rcFile, err := executor.WriteTemp("msf", tools.MetasploitScript(request))
	if err != nil {
		return httpapi.InternalServerError(c, err.Error())
	}
	defer os.Remove(rcFile)
	plan, err := prepareScanExecution(c, request, tools.MetasploitArgs(rcFile))
	if err != nil {
		return scanPreparationError(c, err)
	}
	defer plan.release()
	result := executeOrPreview(c.Context(), plan)
	plan.annotate(result)
	return c.JSON(results.ToToolResult(result))
}

func validateMetasploitRequest(request dto.MetasploitRequest) error {
	if request.Module == "" {
		return fmt.Errorf("module is required")
	}
	if containsLineBreak(request.Module) {
		return fmt.Errorf("module must not contain line breaks")
	}
	for name, value := range request.Options {
		if name == "" {
			return fmt.Errorf("options keys must be non-empty")
		}
		if containsLineBreak(name) || containsLineBreak(value) {
			return fmt.Errorf("options must not contain line breaks")
		}
		if strings.EqualFold(name, "RHOST") || strings.EqualFold(name, "RHOSTS") {
			return fmt.Errorf("RHOST and RHOSTS are set from target_context and cannot be supplied in options")
		}
	}
	if request.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}
