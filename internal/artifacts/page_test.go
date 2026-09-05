package artifacts

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStoreReadsToolResultSectionByLineRange(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(dto.ToolResult{Stdout: "alpha\nbeta\ngamma\n", Stderr: "warning\n"})
	if err != nil {
		t.Fatalf("encode tool result: %v", err)
	}
	reference, err := store.Save(Content{
		Kind: "tool-result-json", MediaType: "application/json", Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactSensitiveUnredacted, Relation: dto.ArtifactRelationToolResult, Payload: payload,
	}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	page, err := store.ReadPage(dto.ArtifactReadRequest{
		ArtifactID: reference.ID, Section: dto.ArtifactSectionStdout, StartLine: 2, LineCount: 1,
	}, now)
	if err != nil {
		t.Fatalf("read stdout lines: %v", err)
	}

	if page.Content != "beta\n" || page.Section != dto.ArtifactSectionStdout {
		t.Fatalf("unexpected section page: %+v", page)
	}
	if page.StartLine != 2 || page.EndLine != 2 || page.NextLine != 3 || page.TotalLines != 3 || !page.HasMore {
		t.Fatalf("unexpected line metadata: %+v", page)
	}
	if page.Offset != int64(len("alpha\n")) || page.NextOffset != int64(len("alpha\nbeta\n")) {
		t.Fatalf("unexpected section offsets: %+v", page)
	}
}

func TestStoreReadsEmptyToolResultSection(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(dto.ToolResult{})
	if err != nil {
		t.Fatalf("encode tool result: %v", err)
	}
	reference, err := store.Save(Content{Kind: "tool-result-json", Encoding: dto.ArtifactEncodingUTF8, Payload: payload}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	page, err := store.ReadPage(dto.ArtifactReadRequest{
		ArtifactID: reference.ID, Section: dto.ArtifactSectionStderr, StartLine: 1, LineCount: 1,
	}, now)
	if err != nil {
		t.Fatalf("read empty stderr: %v", err)
	}
	if page.Content != "" || page.TotalBytes != 0 || page.TotalLines != 0 || page.HasMore {
		t.Fatalf("unexpected empty section page: %+v", page)
	}
}

func TestStoreLinePagingCanReadAnEntireSection(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	stdout := "first\nsecond\nthird"
	payload, err := json.Marshal(dto.ToolResult{Stdout: stdout})
	if err != nil {
		t.Fatalf("encode tool result: %v", err)
	}
	reference, err := store.Save(Content{
		Kind: "tool-result-json", Encoding: dto.ArtifactEncodingUTF8, Payload: payload,
	}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	var collected strings.Builder
	nextLine := 1
	for {
		page, readErr := store.ReadPage(dto.ArtifactReadRequest{
			ArtifactID: reference.ID, Section: dto.ArtifactSectionStdout, StartLine: nextLine, LineCount: 1,
		}, now)
		if readErr != nil {
			t.Fatalf("read line %d: %v", nextLine, readErr)
		}
		collected.WriteString(page.Content)
		if !page.HasMore {
			break
		}
		if page.NextLine <= nextLine {
			t.Fatalf("line cursor did not advance: %+v", page)
		}
		nextLine = page.NextLine
	}
	if collected.String() != stdout {
		t.Fatalf("full section read=%q want=%q", collected.String(), stdout)
	}
}

func TestStoreLongLineCanContinueInByteMode(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	stdout := strings.Repeat("x", maximumPageSize+1024)
	payload, err := json.Marshal(dto.ToolResult{Stdout: stdout})
	if err != nil {
		t.Fatalf("encode tool result: %v", err)
	}
	reference, err := store.Save(Content{Kind: "tool-result-json", Encoding: dto.ArtifactEncodingUTF8, Payload: payload}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	linePage, err := store.ReadPage(dto.ArtifactReadRequest{
		ArtifactID: reference.ID, Section: dto.ArtifactSectionStdout, StartLine: 1, LineCount: 1,
	}, now)
	if err != nil {
		t.Fatalf("read long line: %v", err)
	}
	if !linePage.LineTruncated || !linePage.HasMore || linePage.NextOffset != maximumPageSize {
		t.Fatalf("long line was not bounded: %+v", linePage)
	}

	bytePage, err := store.ReadPage(dto.ArtifactReadRequest{
		ArtifactID: reference.ID, Section: dto.ArtifactSectionStdout,
		Offset: linePage.NextOffset, Limit: maximumPageSize,
	}, now)
	if err != nil {
		t.Fatalf("continue long line: %v", err)
	}
	if linePage.Content+bytePage.Content != stdout || bytePage.HasMore {
		t.Fatalf("byte continuation did not preserve full content: line=%d byte=%d", len(linePage.Content), len(bytePage.Content))
	}
}

func TestStoreRejectsIncompatibleArtifactRanges(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	textReference, err := store.Save(Content{Kind: "text", Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("text\n")}, now)
	if err != nil {
		t.Fatalf("save text artifact: %v", err)
	}
	binaryReference, err := store.Save(Content{Kind: "binary", Encoding: dto.ArtifactEncodingBase64, Payload: []byte{1, 2, 3}}, now)
	if err != nil {
		t.Fatalf("save binary artifact: %v", err)
	}

	requests := []dto.ArtifactReadRequest{
		{ArtifactID: textReference.ID, Offset: 1, StartLine: 1, LineCount: 1},
		{ArtifactID: textReference.ID, Section: dto.ArtifactSectionStdout, Offset: 0, Limit: 256},
		{ArtifactID: binaryReference.ID, StartLine: 1, LineCount: 1},
		{ArtifactID: textReference.ID, StartLine: 1, LineCount: 501},
		{ArtifactID: textReference.ID, Section: dto.ArtifactSection("headers"), Limit: 256},
	}
	for _, request := range requests {
		if _, readErr := store.ReadPage(request, now); !errors.Is(readErr, ErrInvalidPage) {
			t.Fatalf("request %+v returned %v", request, readErr)
		}
	}
}
