package toolapi

import (
	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/gofiber/fiber/v3"
)

func Mount(app *fiber.App, api fiber.Router, limiter *admission.Limiter) {
	api.Post("/command", httpapi.WithExecutionLimit(limiter, handleCommand))
	api.Post("/command/stream", httpapi.WithExecutionLimit(limiter, handleCommandStream))
	api.Get("/tools/capabilities", handleScanCapabilities)
	api.Post("/tools/resolve-target", httpapi.WithExecutionLimit(limiter, handleResolveTarget))
	api.Post("/tools/http-request", httpapi.WithExecutionLimit(limiter, handleHTTPRequest))
	api.Post("/tools/gobuster", httpapi.WithExecutionLimit(limiter, handleGobuster))
	api.Post("/tools/gobuster/stream", httpapi.WithExecutionLimit(limiter, handleGobusterStream))
	api.Post("/tools/nmap/stream", httpapi.WithExecutionLimit(limiter, handleNmapStream))
	api.Post("/tools/dirb/stream", httpapi.WithExecutionLimit(limiter, handleDirbStream))
	api.Post("/tools/nikto/stream", httpapi.WithExecutionLimit(limiter, handleNiktoStream))
	api.Post("/tools/wpscan/stream", httpapi.WithExecutionLimit(limiter, handleWPScanStream))
	api.Post("/tools/enum4linux/stream", httpapi.WithExecutionLimit(limiter, handleEnum4linuxStream))
	api.Post("/tools/sqlmap/stream", httpapi.WithExecutionLimit(limiter, handleSQLMapStream))
	api.Post("/tools/tshark/stream", httpapi.WithExecutionLimit(limiter, handleTsharkStream))
	api.Post("/tools/metasploit", httpapi.WithExecutionLimit(limiter, handleMetasploit))
	api.Post("/tools/hydra", httpapi.WithExecutionLimit(limiter, handleHydra))
	api.Post("/tools/hydra/stream", httpapi.WithExecutionLimit(limiter, handleHydraStream))
	api.Post("/tools/john", httpapi.WithExecutionLimit(limiter, handleJohn))
	api.Post("/tools/ffuf/stream", httpapi.WithExecutionLimit(limiter, handleFFUFStream))
	api.Post("/tools/feroxbuster/stream", httpapi.WithExecutionLimit(limiter, handleFeroxbusterStream))
	api.Post("/tools/nuclei/stream", httpapi.WithExecutionLimit(limiter, handleNucleiStream))
	api.Post("/tools/whatweb/stream", httpapi.WithExecutionLimit(limiter, handleWhatWebStream))
	api.Post("/tools/jwt/stream", httpapi.WithExecutionLimit(limiter, handleJWTStream))
	api.Post("/tools/dalfox/stream", httpapi.WithExecutionLimit(limiter, handleDalfoxStream))
	api.Post("/tools/browser/stream", httpapi.WithExecutionLimit(limiter, handleBrowserStream))
	api.Post("/tools/retire/stream", httpapi.WithExecutionLimit(limiter, handleRetireStream))
	api.Post("/tools/osv/stream", httpapi.WithExecutionLimit(limiter, handleOSVStream))
	app.Get("/health", handleHealth)
}
