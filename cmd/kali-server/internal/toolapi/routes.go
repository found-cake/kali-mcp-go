package toolapi

import (
	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/gofiber/fiber/v3"
)

func Mount(app *fiber.App, api fiber.Router, limiter *admission.Limiter) {
	limited := func(handler fiber.Handler) fiber.Handler {
		return httpapi.WithExecutionLimit(limiter, handler)
	}
	streaming := func(handler fiber.Handler) fiber.Handler {
		return limited(httpapi.WithCallCancellation(handler))
	}
	api.Post("/command", limited(handleCommand))
	api.Post("/command/stream", streaming(handleCommandStream))
	api.Get("/tools/capabilities", handleScanCapabilities)
	api.Post("/tools/resolve-target", limited(handleResolveTarget))
	api.Post("/tools/http-request", limited(handleHTTPRequest))
	api.Post("/tools/gobuster", limited(handleGobuster))
	api.Post("/tools/gobuster/stream", streaming(handleGobusterStream))
	api.Post("/tools/nmap/stream", streaming(handleNmapStream))
	api.Post("/tools/dirb/stream", streaming(handleDirbStream))
	api.Post("/tools/nikto/stream", streaming(handleNiktoStream))
	api.Post("/tools/wpscan/stream", streaming(handleWPScanStream))
	api.Post("/tools/enum4linux/stream", streaming(handleEnum4linuxStream))
	api.Post("/tools/sqlmap/stream", streaming(handleSQLMapStream))
	api.Post("/tools/tshark/stream", streaming(handleTsharkStream))
	api.Post("/tools/metasploit", limited(handleMetasploit))
	api.Post("/tools/hydra", limited(handleHydra))
	api.Post("/tools/hydra/stream", streaming(handleHydraStream))
	api.Post("/tools/john", limited(handleJohn))
	api.Post("/tools/ffuf/stream", streaming(handleFFUFStream))
	api.Post("/tools/feroxbuster/stream", streaming(handleFeroxbusterStream))
	api.Post("/tools/nuclei/stream", streaming(handleNucleiStream))
	api.Post("/tools/whatweb/stream", streaming(handleWhatWebStream))
	api.Post("/tools/jwt/stream", streaming(handleJWTStream))
	api.Post("/tools/dalfox/stream", streaming(handleDalfoxStream))
	api.Post("/tools/browser/stream", streaming(handleBrowserStream))
	api.Post("/tools/retire/stream", streaming(handleRetireStream))
	api.Post("/tools/osv/stream", streaming(handleOSVStream))
	app.Get("/health", handleHealth)
}
