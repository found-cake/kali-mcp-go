package toolapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	httpapi "github.com/found-cake/kali-mcp-go/cmd/kali-server/internal/httpapi"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestPreviewNucleiTemplatesReturnsLocalSelectionCount(t *testing.T) {
	// Given: a local Nuclei executable that lists two selected templates.
	directory := t.TempDir()
	executable := filepath.Join(directory, "nuclei")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'one.yaml\\ntwo.yaml\\n'\n"), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	t.Setenv("PATH", directory)
	request := dto.NucleiRequest{Target: "https://example.test", Tags: "exposure", DryRun: true}

	// When: the server prepares a non-network preview.
	preview, err := previewNucleiTemplates(context.Background(), request)
	// Then: the selected template count is returned without target requests.
	if err != nil {
		t.Fatalf("preview Nuclei templates: %v", err)
	}
	if preview.TemplatesMatched != 2 || preview.SelectionSource != "tags" || preview.TargetRequestsSent != 0 {
		t.Fatalf("unexpected Nuclei preview: %+v", preview)
	}
}

func TestDecorateNucleiExecutionSkipsPreviewForActualScan(t *testing.T) {
	// Given: an actual scan and a local preview executable whose invocation is observable.
	directory := t.TempDir()
	executable := filepath.Join(directory, "nuclei")
	marker := filepath.Join(directory, "preview-invoked")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf invoked > \"$NUCLEI_PREVIEW_MARKER\"\nprintf 'template.yaml\\n'\n"), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	t.Setenv("NUCLEI_PREVIEW_MARKER", marker)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	request := dto.NucleiRequest{Target: "https://example.test", Tags: "exposure"}
	plan := &scanExecutionPlan{context: t.Context(), timeout: 3 * time.Second}

	// When: the real scan plan is decorated.
	err := decorateNucleiExecution(request, plan)

	// Then: no local template preview or duration estimation runs implicitly.
	if err != nil {
		t.Fatalf("decorate Nuclei execution: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("normal scan invoked Nuclei preview: %v", err)
	}
	if plan.nucleiPreview != nil || len(plan.extraWarnings) != 0 {
		t.Fatalf("normal scan retained preview metadata: preview=%+v warnings=%v", plan.nucleiPreview, plan.extraWarnings)
	}
}

func TestDecorateNucleiExecutionReportsDryRunPreviewFailure(t *testing.T) {
	// Given: an explicit dry run and a local Nuclei command that cannot enumerate templates.
	directory := t.TempDir()
	executable := filepath.Join(directory, "nuclei")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'template database unavailable' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	request := dto.NucleiRequest{Target: "https://example.test", Tags: "exposure", DryRun: true}
	plan := &scanExecutionPlan{context: t.Context(), timeout: time.Minute}

	// When: the requested local preview fails.
	err := decorateNucleiExecution(request, plan)

	// Then: the dry run reports the preview error instead of pretending it completed.
	if err == nil || !strings.Contains(err.Error(), "template database unavailable") {
		t.Fatalf("dry-run preview failure was hidden: %v", err)
	}
}

func TestNucleiPreviewRegistersCancellationBeforeListingTemplates(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "started")
	if err := syscall.Mkfifo(marker, 0o600); err != nil {
		t.Fatalf("create preview signal: %v", err)
	}
	markerReader, err := os.OpenFile(marker, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open preview signal: %v", err)
	}
	defer markerReader.Close()
	previewStarted := make(chan error, 1)
	go func() {
		var signal [1]byte
		_, readErr := io.ReadFull(markerReader, signal[:])
		previewStarted <- readErr
	}()
	executable := filepath.Join(directory, "nuclei")
	script := "#!/bin/sh\nprintf x > \"$NUCLEI_PREVIEW_MARKER\"\nsleep 30\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake nuclei: %v", err)
	}
	t.Setenv("NUCLEI_PREVIEW_MARKER", marker)
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))

	app := fiber.New()
	registry := httpapi.NewCallCancellationRegistry()
	limiter := httpapi.NewExecutionLimiter(1)
	app.Use(httpapi.CallTelemetryMiddleware(nil))
	app.Use(httpapi.CallCancellationRegistryMiddleware(registry))
	app.Use(httpapi.BearerAuthMiddleware("test-secret"))
	app.Post("/nuclei", httpapi.WithExecutionLimit(limiter, httpapi.WithCallCancellation(handleNucleiStream)))
	app.Post("/calls/:id/cancel", httpapi.HandleCancelCall)
	app.Get("/probe", httpapi.WithExecutionLimit(limiter, func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- app.Listener(listener, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() {
		_ = app.Shutdown()
		<-serverDone
	})

	callID := "call_0123456789abcdef0123456789abcdef"
	payload, err := json.Marshal(dto.NucleiRequest{
		ScanOptions: dto.ScanOptions{TargetContext: signedHighImpactContext(t), Profile: dto.ProfileSafeRecon},
		Tags:        "exposure",
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("marshal preview request: %v", err)
	}
	previewRequest, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/nuclei", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create preview request: %v", err)
	}
	previewRequest.Header.Set(fiber.HeaderAuthorization, "Bearer test-secret")
	previewRequest.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	previewRequest.Header.Set(dto.CallIDHeader, callID)
	previewDone := make(chan *http.Response, 1)
	previewFailed := make(chan error, 1)
	go func() {
		response, requestErr := http.DefaultClient.Do(previewRequest)
		if requestErr != nil {
			previewFailed <- requestErr
			return
		}
		previewDone <- response
	}()
	select {
	case err := <-previewStarted:
		if err != nil {
			t.Fatalf("read preview signal: %v", err)
		}
	case err := <-previewFailed:
		t.Fatalf("preview request failed before starting: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Nuclei preview did not start")
	}

	cancelRequest, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/calls/%s/cancel", listener.Addr(), callID), nil)
	if err != nil {
		t.Fatalf("create cancel request: %v", err)
	}
	cancelRequest.Header.Set(fiber.HeaderAuthorization, "Bearer test-secret")
	cancelResponse, err := http.DefaultClient.Do(cancelRequest)
	if err != nil {
		t.Fatalf("cancel preview: %v", err)
	}
	cancelResponse.Body.Close()
	if cancelResponse.StatusCode != fiber.StatusAccepted {
		t.Fatalf("cancel status=%d want=%d", cancelResponse.StatusCode, fiber.StatusAccepted)
	}

	select {
	case response := <-previewDone:
		response.Body.Close()
		if response.StatusCode != fiber.StatusBadRequest {
			t.Fatalf("cancelled preview status=%d", response.StatusCode)
		}
	case err := <-previewFailed:
		t.Fatalf("preview request failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled preview retained its execution lease")
	}
	probeRequest, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/probe", nil)
	if err != nil {
		t.Fatalf("create probe request: %v", err)
	}
	probeRequest.Header.Set(fiber.HeaderAuthorization, "Bearer test-secret")
	probeResponse, err := http.DefaultClient.Do(probeRequest)
	if err != nil {
		t.Fatalf("probe released capacity: %v", err)
	}
	probeResponse.Body.Close()
	if probeResponse.StatusCode != fiber.StatusOK {
		t.Fatalf("preview retained execution capacity: status=%d", probeResponse.StatusCode)
	}
}
