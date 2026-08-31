package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/gofiber/fiber/v3"
)

func TestArtifactHandlerReturnsOriginalMediaTypeAndPayload(t *testing.T) {
	// Given: an authenticated artifact route with retained text evidence.
	app, store := newArtifactHandlerTestApp(t)
	reference, err := store.Save(artifactstore.Content{
		Kind: "evidence", MediaType: "text/plain", Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactSensitiveUnredacted, Payload: []byte("raw evidence"),
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "/api/artifacts/"+reference.ID, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-token")

	// When: the raw artifact endpoint is requested.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request artifact: %v", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Then: the route preserves status, media type, and bytes.
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/plain" || string(payload) != "raw evidence" {
		t.Fatalf("unexpected artifact response: status=%d type=%q body=%q", response.StatusCode, response.Header.Get("Content-Type"), payload)
	}
}

func TestArtifactPageHandlerAddsCallID(t *testing.T) {
	// Given: an authenticated paged artifact route.
	app, store := newArtifactHandlerTestApp(t)
	reference, err := store.Save(artifactstore.Content{
		Kind: "evidence", MediaType: "text/plain", Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactSensitiveUnredacted, SourceCallID: "source-call", Payload: []byte("raw evidence"),
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "/api/artifacts/"+reference.ID+"/page?limit=256", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-token")

	// When: the paged endpoint is requested.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request artifact page: %v", err)
	}
	defer response.Body.Close()
	var page dto.ArtifactReadResult
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatalf("decode page: %v", err)
	}

	// Then: the HTTP call and source artifact identities are both preserved.
	if response.StatusCode != http.StatusOK || page.CallID == "" || page.SourceCallID != "source-call" || page.Content != "raw evidence" {
		t.Fatalf("unexpected artifact page: status=%d page=%+v", response.StatusCode, page)
	}
}

func TestArtifactHandlersPreserveErrorMapping(t *testing.T) {
	app, _ := newArtifactHandlerTestApp(t)
	tests := []struct {
		name   string
		path   string
		status int
		body   string
	}{
		{name: "raw missing", path: "/api/artifacts/missing", status: http.StatusNotFound, body: artifactstore.ErrNotFound.Error()},
		{name: "page missing", path: "/api/artifacts/missing/page", status: http.StatusNotFound, body: artifactstore.ErrNotFound.Error()},
		{name: "invalid offset", path: "/api/artifacts/missing/page?offset=text", status: http.StatusBadRequest, body: "offset must be an integer"},
		{name: "invalid limit", path: "/api/artifacts/missing/page?limit=text", status: http.StatusBadRequest, body: "limit must be an integer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: an authenticated artifact request for an invalid resource or query.
			request, err := http.NewRequest(http.MethodGet, test.path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set("Authorization", "Bearer test-token")

			// When: the artifact route handles the request.
			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("request artifact: %v", err)
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			var body struct {
				Error string `json:"error"`
			}
			decodeErr := json.Unmarshal(payload, &body)

			// Then: the existing status and public error text remain stable.
			if response.StatusCode != test.status || decodeErr != nil || body.Error != test.body {
				t.Fatalf("unexpected error response: status=%d body=%s", response.StatusCode, payload)
			}
		})
	}
}

func TestArtifactPageHandlerMapsInvalidPageToBadRequest(t *testing.T) {
	// Given: a stored artifact and a numeric page size below the supported minimum.
	app, store := newArtifactHandlerTestApp(t)
	reference, err := store.Save(artifactstore.Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("evidence")}, time.Now().UTC())
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "/api/artifacts/"+reference.ID+"/page?limit=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-token")

	// When: the paged endpoint validates the requested range.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request artifact page: %v", err)
	}
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Then: the store error keeps the existing HTTP 400 mapping.
	if response.StatusCode != http.StatusBadRequest || body.Error != artifactstore.ErrInvalidPage.Error() {
		t.Fatalf("unexpected invalid-page response: status=%d body=%+v", response.StatusCode, body)
	}
}

func newArtifactHandlerTestApp(t *testing.T) (*fiber.App, *artifactstore.Store) {
	t.Helper()
	store, err := artifactstore.New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	app := fiber.New()
	app.Use(CallTelemetryMiddleware(t.Logf))
	app.Use(ArtifactStoreMiddleware(store))
	api := app.Group("/api", BearerAuthMiddleware("test-token"))
	api.Get("/artifacts/:id", HandleGetArtifact)
	api.Get("/artifacts/:id/page", HandleGetArtifactPage)
	return app, store
}
