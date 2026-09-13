package artifacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func BenchmarkStoreReadRawBytePage(b *testing.B) {
	tests := []struct {
		name     string
		size     int
		encoding dto.ArtifactEncoding
	}{
		{name: "1MiB", size: 1 << 20, encoding: dto.ArtifactEncodingUTF8},
		{name: "64MiB", size: 64 << 20, encoding: dto.ArtifactEncodingUTF8},
		{name: "base64_1MiB", size: 1 << 20, encoding: dto.ArtifactEncodingBase64},
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
				Kind: "fixture", Encoding: test.encoding, Payload: payload,
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
			wantLength := maximumPageSize
			if test.encoding == dto.ArtifactEncodingBase64 {
				wantLength = base64.StdEncoding.EncodedLen(maximumPageSize)
			}

			b.ReportAllocs()
			b.SetBytes(maximumPageSize)
			b.ResetTimer()
			for b.Loop() {
				page, readErr := store.ReadPage(request, now)
				if readErr != nil {
					b.Fatalf("read page: %v", readErr)
				}
				if len(page.Content) != wantLength {
					b.Fatalf("page length=%d want=%d", len(page.Content), wantLength)
				}
			}
		})
	}
}

func BenchmarkStoreReadSection(b *testing.B) {
	for _, test := range []struct {
		name string
		size int
	}{
		{name: "1MiB", size: 1 << 20},
		{name: "16MiB", size: 16 << 20},
	} {
		for _, mode := range []string{"bytes", "lines"} {
			b.Run(test.name+"/"+mode, func(b *testing.B) {
				store, err := New()
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() {
					if err := store.Close(); err != nil {
						b.Error(err)
					}
				})
				now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
				payload, err := json.Marshal(struct {
					Stdout string `json:"stdout"`
					Stderr string `json:"stderr"`
				}{Stdout: strings.Repeat("record\n", test.size/7), Stderr: "warning\n"})
				if err != nil {
					b.Fatal(err)
				}
				reference, err := store.Save(Content{Kind: "tool-result-json", Encoding: dto.ArtifactEncodingUTF8, Payload: payload}, now)
				if err != nil {
					b.Fatal(err)
				}
				request := dto.ArtifactReadRequest{ArtifactID: reference.ID, Section: dto.ArtifactSectionStdout}
				wantLength := defaultPageSize
				if mode == "lines" {
					request.StartLine = 1
					request.LineCount = 100
					wantLength = 700
				}
				payload = nil
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					page, err := store.ReadPage(request, now)
					if err != nil || len(page.Content) != wantLength {
						b.Fatalf("unexpected section page: err=%v bytes=%d", err, len(page.Content))
					}
				}
			})
		}
	}
}
