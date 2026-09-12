package artifacts

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type trackingReaderAt struct {
	reader  io.ReaderAt
	maxRead int
}

func (reader *trackingReaderAt) ReadAt(payload []byte, offset int64) (int, error) {
	reader.maxRead = max(reader.maxRead, len(payload))
	return reader.reader.ReadAt(payload, offset)
}

func TestReadRawBytePageReadsOnlyBoundedWindow(t *testing.T) {
	// Given: a raw artifact much larger than the maximum page size.
	payload := bytes.Repeat([]byte("x"), maximumPageSize*4)
	reader := &trackingReaderAt{reader: bytes.NewReader(payload)}
	source := rawPageSource{
		reference: dto.ArtifactRef{Encoding: dto.ArtifactEncodingUTF8},
		reader:    reader,
		total:     int64(len(payload)),
	}

	// When: a maximum-size page is read from the middle.
	page, err := readRawBytePage(source, dto.ArtifactReadRequest{
		ArtifactID: "artifact-test", Offset: maximumPageSize, Limit: maximumPageSize,
	}, time.Date(2026, time.September, 8, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("read raw page: %v", err)
	}

	// Then: only the page and one UTF-8 boundary byte are read.
	if reader.maxRead > maximumPageSize+1 {
		t.Fatalf("source read=%d want<=%d", reader.maxRead, maximumPageSize+1)
	}
	if len(page.Content) != maximumPageSize || page.NextOffset != maximumPageSize*2 || !page.HasMore {
		t.Fatalf("unexpected bounded page: %+v", page)
	}
}

func TestStoreRawBytePagePreservesBoundariesAndMetadata(t *testing.T) {
	// Given: a UTF-8 artifact whose requested boundary splits a rune.
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 8, 10, 0, 0, 0, time.UTC)
	payload := []byte(strings.Repeat("a", 255) + "한" + strings.Repeat("z", 256))
	reference, err := store.Save(Content{
		Kind: "text", MediaType: "text/plain", Encoding: dto.ArtifactEncodingUTF8,
		RedactionState: dto.ArtifactSensitiveUnredacted, SourceCallID: "call-source",
		Relation: dto.ArtifactRelationToolResult, Payload: payload,
	}, now)
	if err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	// When: the first page and the exact EOF cursor are read.
	page, err := store.ReadPage(dto.ArtifactReadRequest{ArtifactID: reference.ID, Limit: 256}, now)
	if err != nil {
		t.Fatalf("read UTF-8 page: %v", err)
	}
	eofPage, err := store.ReadPage(dto.ArtifactReadRequest{
		ArtifactID: reference.ID, Offset: int64(len(payload)), Limit: 256,
	}, now)
	if err != nil {
		t.Fatalf("read EOF page: %v", err)
	}

	// Then: byte cursors, UTF-8 boundaries, provenance, and expiry stay unchanged.
	if page.Content != strings.Repeat("a", 255) || page.Offset != 0 || page.NextOffset != 255 || !page.HasMore {
		t.Fatalf("unexpected UTF-8 boundary page: %+v", page)
	}
	if page.TotalBytes != int64(len(payload)) || page.SourceCallID != "call-source" || page.MediaType != "text/plain" || page.Encoding != dto.ArtifactEncodingUTF8 || page.RedactionState != dto.ArtifactSensitiveUnredacted || page.Relation != dto.ArtifactRelationToolResult {
		t.Fatalf("unexpected page metadata: %+v", page)
	}
	if !page.ExpiresAt.Equal(reference.ExpiresAt) || page.ExpiresInSeconds != int64(artifactTTL/time.Second) || page.ExpiringSoon {
		t.Fatalf("unexpected expiry metadata: %+v", page)
	}
	if eofPage.Content != "" || eofPage.Offset != int64(len(payload)) || eofPage.NextOffset != int64(len(payload)) || eofPage.HasMore {
		t.Fatalf("unexpected EOF page: %+v", eofPage)
	}
}

func TestStoreRawBytePagePreservesErrorPrecedence(t *testing.T) {
	// Given: missing, expired, and deleted artifacts paired with invalid page inputs.
	store, err := New()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.September, 8, 10, 0, 0, 0, time.UTC)
	expired, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("expired")}, now)
	if err != nil {
		t.Fatalf("save expired artifact: %v", err)
	}
	deleted, err := store.Save(Content{Encoding: dto.ArtifactEncodingUTF8, Payload: []byte("deleted")}, now)
	if err != nil {
		t.Fatalf("save deleted artifact: %v", err)
	}
	if err := os.Remove(store.items[deleted.ID].path); err != nil {
		t.Fatalf("remove backing file: %v", err)
	}
	tests := []struct {
		name    string
		request dto.ArtifactReadRequest
		at      time.Time
	}{
		{name: "missing", request: dto.ArtifactReadRequest{ArtifactID: "missing", Limit: 1}, at: now},
		{name: "expired", request: dto.ArtifactReadRequest{ArtifactID: expired.ID, Offset: -1}, at: now.Add(artifactTTL + time.Second)},
		{name: "deleted", request: dto.ArtifactReadRequest{ArtifactID: deleted.ID, Limit: 1}, at: now},
	}

	// When/Then: artifact identity and lifetime errors precede page validation.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, readErr := store.ReadPage(test.request, test.at); !errors.Is(readErr, ErrNotFound) {
				t.Fatalf("read page: %v", readErr)
			}
		})
	}
}
