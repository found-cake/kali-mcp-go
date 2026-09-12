package toolapi

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/internal/results"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

var (
	metasploitModuleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]*$`)
	metasploitOptionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]*$`)
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
	plan, err := prepareScanExecution(c, request, tools.MetasploitArgs(rcFile))
	if err != nil {
		_ = os.Remove(rcFile)
		return scanPreparationError(c, err)
	}
	if plan.async {
		return executeAsyncTool(c, streamExecution{
			plan: plan, cleanups: []func(){func() { _ = os.Remove(rcFile) }},
		})
	}
	defer plan.release()
	defer os.Remove(rcFile)
	result := executeOrPreview(c.Context(), plan)
	plan.annotate(result)
	return c.JSON(results.ToToolResult(result))
}

func validateMetasploitRequest(request dto.MetasploitRequest) error {
	if request.Module == "" {
		return fmt.Errorf("module is required")
	}
	if !metasploitModuleName.MatchString(request.Module) {
		return fmt.Errorf("module contains unsupported resource-script characters")
	}
	for name, value := range request.Options {
		if !metasploitOptionName.MatchString(name) {
			return fmt.Errorf("option names contain unsupported resource-script characters")
		}
		if strings.ContainsRune(value, ';') || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("option values contain unsupported resource-script characters")
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
