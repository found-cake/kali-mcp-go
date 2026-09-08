package artifacts

import (
	"bytes"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func BenchmarkStoreReadRawBytePage(b *testing.B) {
	tests := []struct {
		name string
		size int
	}{
		{name: "1MiB", size: 1 << 20},
		{name: "64MiB", size: 64 << 20},
	}

	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			store, err := New()
			if err != nil {
				b.Fatalf("create store: %v", err)
			}
			b.Cleanup(func() { _ = store.Close() })
			now := time.Date(2026, time.September, 8, 10, 0, 0, 0, time.UTC)
			payload := bytes.Repeat([]byte("x"), test.size)
			reference, err := store.Save(Content{
				Kind: "text", Encoding: dto.ArtifactEncodingUTF8, Payload: payload,
			}, now)
			if err != nil {
				b.Fatalf("save artifact: %v", err)
			}
			request := dto.ArtifactReadRequest{
				ArtifactID: reference.ID,
				Offset:     int64(test.size / 2),
				Limit:      maximumPageSize,
			}
			payload = nil

			b.ReportAllocs()
			b.SetBytes(maximumPageSize)
			b.ResetTimer()
			for b.Loop() {
				page, readErr := store.ReadPage(request, now)
				if readErr != nil {
					b.Fatalf("read page: %v", readErr)
				}
				if len(page.Content) != maximumPageSize {
					b.Fatalf("page length=%d want=%d", len(page.Content), maximumPageSize)
				}
			}
		})
	}
}
