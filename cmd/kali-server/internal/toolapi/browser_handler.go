package toolapi

import (
	"os"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

func handleBrowserStream(c fiber.Ctx) error {
	request, err := httpapi.ParseRequest(c, validateBrowserRequest)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	args, err := tools.BrowserArgs(request)
	if err != nil {
		return httpapi.BadRequest(c, err.Error())
	}
	plan, err := prepareScanExecution(c, request, args)
	if err != nil {
		return scanPreparationError(c, err)
	}
	if request.CaptureScreenshot {
		path, pathErr := newBrowserScreenshotPath()
		if pathErr != nil {
			plan.release()
			return httpapi.InternalServerError(c, pathErr.Error())
		}
		plan.args = append(plan.args, "--screenshot-path", path)
		plan.browserScreenshotPath = path
		previousRelease := plan.release
		plan.release = func() {
			previousRelease()
			_ = os.Remove(path)
		}
	}
	return executeStreamPlan(c, plan)
}

func newBrowserScreenshotPath() (string, error) {
	file, err := os.CreateTemp("", "kali-mcp-browser-*.jpg")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}
