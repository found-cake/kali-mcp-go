package main

import (
	"time"

	"github.com/found-cake/kali-mcp-go/internal/httpexec"
	"github.com/found-cake/kali-mcp-go/internal/targeting"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func handleHTTPRequest(c fiber.Ctx) error {
	request, err := parseRequest(c, httpexec.Validate)
	if err != nil {
		return badRequest(c, err.Error())
	}
	if err := tools.ValidateScanProfile("http-request", request.ScanOptions); err != nil {
		return badRequest(c, err.Error())
	}
	provenance, err := targeting.ResolveProvenance(request, apiTokenFromContext(c), time.Now().UTC())
	if err != nil {
		return badRequest(c, err.Error())
	}
	release := func() {}
	if scheduler := schedulerFromContext(c); scheduler != nil {
		release, err = scheduler.Acquire(request.URL, 1)
		if err != nil {
			return scanPreparationError(c, err)
		}
	}
	defer release()
	result := httpexec.Execute(c.Context(), httpexec.Input{
		CallID: callIDFromContext(c), Request: request, Target: provenance,
	})
	return writeToolResult(c, result, request)
}
