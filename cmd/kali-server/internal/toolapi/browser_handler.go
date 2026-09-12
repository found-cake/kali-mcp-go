package toolapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/internal/tools"
	"github.com/gofiber/fiber/v3"
)

const browserOutputDirectoryEnv = "KALI_MCP_BROWSER_OUTPUT_DIR"

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
	if len(request.Headers) > 0 {
		path, pathErr := newBrowserHeadersPath(request.Headers)
		if pathErr != nil {
			plan.release()
			return httpapi.InternalServerError(c, pathErr.Error())
		}
		plan.args = append(plan.args, "--headers-file", path)
		plan.ephemeralPaths = append(plan.ephemeralPaths, path)
		addBrowserFileCleanup(plan, path)
	}
	if len(request.LocalStorage) > 0 {
		path, pathErr := newBrowserLocalStoragePath(request.LocalStorage)
		if pathErr != nil {
			plan.release()
			return httpapi.InternalServerError(c, pathErr.Error())
		}
		plan.args = append(plan.args, "--local-storage-file", path)
		plan.ephemeralPaths = append(plan.ephemeralPaths, path)
		addBrowserFileCleanup(plan, path)
	}
	if request.CaptureScreenshot {
		path, pathErr := newBrowserScreenshotPath()
		if pathErr != nil {
			plan.release()
			return httpapi.InternalServerError(c, pathErr.Error())
		}
		plan.args = append(plan.args, "--screenshot-path", path)
		plan.browserScreenshotPath = path
		addBrowserFileCleanup(plan, path)
	}
	return executeStreamPlan(c, plan)
}

func newBrowserScreenshotPath() (string, error) {
	return newBrowserHandoffFile("kali-mcp-browser-*.jpg", nil, 0o620)
}

func newBrowserHeadersPath(headers map[string]string) (string, error) {
	return newBrowserStringMapPath("headers", "kali-mcp-browser-headers-*.json", headers)
}

func newBrowserLocalStoragePath(values map[string]string) (string, error) {
	return newBrowserStringMapPath("local storage", "kali-mcp-browser-storage-*.json", values)
}

func newBrowserStringMapPath(label, pattern string, values map[string]string) (string, error) {
	content, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("encode browser %s: %w", label, err)
	}
	return newBrowserHandoffFile(pattern, content, 0o640)
}

func newBrowserHandoffFile(pattern string, content []byte, containerMode os.FileMode) (string, error) {
	directory := os.Getenv(browserOutputDirectoryEnv)
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if len(content) > 0 {
		if _, err := file.Write(content); err != nil {
			return "", errors.Join(err, file.Close(), os.Remove(path))
		}
	}
	if directory != "" {
		if err := file.Chmod(containerMode); err != nil {
			return "", errors.Join(err, file.Close(), os.Remove(path))
		}
	}
	if err := file.Close(); err != nil {
		return "", errors.Join(err, os.Remove(path))
	}
	return path, nil
}

func addBrowserFileCleanup(plan *scanExecutionPlan, path string) {
	previousRelease := plan.release
	plan.release = func() {
		previousRelease()
		_ = os.Remove(path)
	}
}
