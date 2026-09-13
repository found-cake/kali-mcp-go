package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestArtifactPageHandlerReadsToolOutputLines(t *testing.T) {
	app, store := newArtifactHandlerTestApp(t)
	payload, err := json.Marshal(dto.ToolResult{Stdout: "one\ntwo\nthree\n"})
	if err != nil {
		t.Fatalf("encode tool result: %v", err)
	}
	reference, err := store.Save(artifactstore.Content{
		Kind: "tool-result-json", MediaType: "application/json", Encoding: dto.ArtifactEncodingUTF8, Payload: payload,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet,
		"/api/artifacts/"+reference.ID+"/page?section=stdout&start_line=2&line_count=1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-token")

	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request artifact page: %v", err)
	}
	defer response.Body.Close()
	var page dto.ArtifactReadResult
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	if response.StatusCode != http.StatusOK || page.Content != "two\n" || page.StartLine != 2 || page.NextLine != 3 {
		t.Fatalf("unexpected line page: status=%d page=%+v", response.StatusCode, page)
	}
}

func TestArtifactPageHandlerRejectsInvalidLineQueries(t *testing.T) {
	app, _ := newArtifactHandlerTestApp(t)
	for _, path := range []string{
		"/api/artifacts/missing/page?start_line=text",
		"/api/artifacts/missing/page?line_count=text",
	} {
		request, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		request.Header.Set("Authorization", "Bearer test-token")
		response, err := app.Test(request)
		if err != nil {
			t.Fatalf("request artifact page: %v", err)
		}
		if response.StatusCode != http.StatusBadRequest {
			response.Body.Close()
			t.Fatalf("unexpected status for %s: %d", path, response.StatusCode)
		}
		response.Body.Close()
	}
}
