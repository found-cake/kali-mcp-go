package toolapi

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/found-cake/kali-mcp-go/internal/admission"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestScanPreparationErrorReturnsTypedCapacityDetails(t *testing.T) {
	// Given: an HTTP handler receiving a target-scoped scheduler rejection.
	scheduler := admission.NewScheduler(4, 3)
	release, err := scheduler.Acquire("target-a", 3)
	if err != nil {
		t.Fatalf("acquire target capacity: %v", err)
	}
	defer release()
	_, capacityErr := scheduler.Acquire("target-a", 1)
	app := fiber.New()
	app.Get("/scan", func(c fiber.Ctx) error {
		return scanPreparationError(c, capacityErr)
	})

	// When: the error crosses the Kali server HTTP boundary.
	request, err := http.NewRequest(http.MethodGet, "/scan", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request scan: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var failure dto.ErrorResponse
	if err := json.Unmarshal(body, &failure); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Then: callers can branch on a stable code and inspect capacity without parsing prose.
	if response.StatusCode != fiber.StatusServiceUnavailable || failure.Code != dto.FailureCodeTargetCapacityExceeded {
		t.Fatalf("unexpected capacity response: status=%d body=%s", response.StatusCode, body)
	}
	if failure.Capacity == nil || failure.Capacity.Scope != dto.CapacityScopeTarget || failure.Capacity.Used != 3 || failure.Capacity.Limit != 3 || failure.Capacity.RequestedWeight != 1 {
		t.Fatalf("unexpected capacity details: %+v", failure.Capacity)
	}
}
