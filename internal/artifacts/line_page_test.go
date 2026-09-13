package artifacts

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestReadLinePageBoundaries(t *testing.T) {
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	reference := dto.ArtifactRef{Encoding: dto.ArtifactEncodingUTF8, ExpiresAt: now.Add(time.Hour)}
	tests := []struct {
		name                     string
		payload                  string
		start, count             int
		content                  string
		offset, nextOffset       int64
		first, last, next, total int
		more, truncated, invalid bool
	}{
		{name: "empty", start: 1, count: 1, first: 1},
		{name: "empty beyond end", start: 2, count: 1, invalid: true},
		{name: "blank lines", payload: "\n\na\n", start: 2, count: 1, content: "\n", offset: 1, nextOffset: 2, first: 2, last: 2, next: 3, total: 3, more: true},
		{name: "terminal newline", payload: "a\n", start: 1, count: 5, content: "a\n", nextOffset: 2, first: 1, last: 1, total: 1},
		{name: "unterminated last line", payload: "a\nb", start: 2, count: 5, content: "b", offset: 2, nextOffset: 3, first: 2, last: 2, total: 2},
		{name: "beyond end", payload: "a\n", start: 2, count: 1, invalid: true},
		{name: "negative start", payload: "a", start: -1, count: 1, invalid: true},
		{name: "negative count", payload: "a", start: 1, count: -1, invalid: true},
		{name: "count too large", payload: "a", start: 1, count: 501, invalid: true},
		{name: "default start", payload: "a\nb", count: 1, content: "a\n", nextOffset: 2, first: 1, last: 1, next: 2, total: 2, more: true},
		{name: "default count", payload: strings.Repeat("a\n", 101), start: 1, content: strings.Repeat("a\n", 100), nextOffset: 200, first: 1, last: 100, next: 101, total: 101, more: true},
		{name: "maximum count", payload: strings.Repeat("a\n", 501), start: 1, count: 500, content: strings.Repeat("a\n", 500), nextOffset: 1000, first: 1, last: 500, next: 501, total: 501, more: true},
		{name: "exact byte cap", payload: strings.Repeat("a", maximumPageSize-1) + "\nb", start: 1, count: 2, content: strings.Repeat("a", maximumPageSize-1) + "\n", nextOffset: maximumPageSize, first: 1, last: 1, next: 2, total: 2, more: true},
		{name: "defer oversized second line", payload: "a\n" + strings.Repeat("b", maximumPageSize), start: 1, count: 2, content: "a\n", nextOffset: 2, first: 1, last: 1, next: 2, total: 2, more: true},
		{name: "utf8 truncation after prefix", payload: "a\n" + strings.Repeat("한", maximumPageSize/3+1), start: 2, count: 1, content: strings.Repeat("한", maximumPageSize/3), offset: 2, nextOffset: 2 + maximumPageSize/3*3, first: 2, last: 2, next: 2, total: 2, more: true, truncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := dto.ArtifactReadRequest{ArtifactID: "fixture", StartLine: test.start, LineCount: test.count}
			page, err := readLinePage(reference, request, dto.ArtifactSectionRaw, pageText{data: []byte(test.payload)}, now)
			if test.invalid {
				if !errors.Is(err, ErrInvalidPage) {
					t.Fatalf("error=%v want=%v", err, ErrInvalidPage)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if page.Content != test.content || page.Offset != test.offset || page.NextOffset != test.nextOffset ||
				page.StartLine != test.first || page.EndLine != test.last || page.NextLine != test.next ||
				page.TotalLines != test.total || page.HasMore != test.more || page.LineTruncated != test.truncated {
				t.Fatalf("unexpected page: offsets=%d:%d lines=%d:%d next=%d total=%d more=%v truncated=%v content bytes=%d",
					page.Offset, page.NextOffset, page.StartLine, page.EndLine, page.NextLine, page.TotalLines, page.HasMore, page.LineTruncated, len(page.Content))
			}
			if page.TotalBytes != int64(len(test.payload)) || page.ArtifactID != request.ArtifactID ||
				page.Section != dto.ArtifactSectionRaw || page.Encoding != reference.Encoding || page.ExpiresAt != reference.ExpiresAt {
				t.Fatal("page metadata changed")
			}
		})
	}
}

func TestReadLinePageEveryRange(t *testing.T) {
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	reference := dto.ArtifactRef{Encoding: dto.ArtifactEncodingUTF8}
	for _, payload := range []string{"\nfirst\n\n한글\nlast", "\nfirst\n\n한글\nlast\n", "\n\n\n\n\n\n", "a\r\nb\rc\nd\ne\nf"} {
		lines := strings.SplitAfter(payload, "\n")
		if lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		for first := 1; first <= len(lines); first++ {
			for count := 1; count <= len(lines)+1; count++ {
				last := min(first-1+count, len(lines))
				want := strings.Join(lines[first-1:last], "")
				offset := len(strings.Join(lines[:first-1], ""))
				request := dto.ArtifactReadRequest{StartLine: first, LineCount: count}
				page, err := readLinePage(reference, request, dto.ArtifactSectionRaw, pageText{data: []byte(payload)}, now)
				if err != nil {
					t.Fatal(err)
				}
				if page.Content != want || page.Offset != int64(offset) || page.NextOffset != int64(offset+len(want)) ||
					page.StartLine != first || page.EndLine != last || page.TotalLines != len(lines) || page.HasMore != (last < len(lines)) {
					t.Fatalf("payload=%q first=%d count=%d: unexpected page %+v", payload, first, count, page)
				}
			}
		}
	}
}

func BenchmarkReadLinePage(b *testing.B) {
	for _, test := range []struct {
		name  string
		lines int
		start int
	}{
		{name: "10K/head", lines: 10_000, start: 1},
		{name: "1M/head", lines: 1_000_000, start: 1},
		{name: "1M/middle", lines: 1_000_000, start: 500_000},
		{name: "1M/tail", lines: 1_000_000, start: 999_901},
	} {
		b.Run(test.name, func(b *testing.B) {
			payload := []byte(strings.Repeat("line\n", test.lines))
			now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
			reference := dto.ArtifactRef{Encoding: dto.ArtifactEncodingUTF8}
			request := dto.ArtifactReadRequest{StartLine: test.start, LineCount: 100}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				page, err := readLinePage(reference, request, dto.ArtifactSectionRaw, pageText{data: payload}, now)
				if err != nil || len(page.Content) != 500 || page.TotalLines != test.lines {
					b.Fatalf("invalid line page: err=%v bytes=%d lines=%d", err, len(page.Content), page.TotalLines)
				}
			}
		})
	}
}

func TestReadLinePageAcrossSearchBlocks(t *testing.T) {
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	reference := dto.ArtifactRef{Encoding: dto.ArtifactEncodingUTF8}
	for _, payload := range []string{strings.Repeat("\n", 8193), strings.Repeat("record\n", 4096), strings.Repeat("ab\n", 4096) + "last"} {
		lines := strings.SplitAfter(payload, "\n")
		if lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		for _, start := range []int{1, 2, len(lines) / 2, len(lines)/2 + 1, len(lines) - 1, len(lines)} {
			last := min(start-1+100, len(lines))
			want := strings.Join(lines[start-1:last], "")
			offset := len(strings.Join(lines[:start-1], ""))
			request := dto.ArtifactReadRequest{StartLine: start, LineCount: 100}
			for _, representation := range []pageText{{data: []byte(payload)}, {text: payload}} {
				page, err := readLinePage(reference, request, dto.ArtifactSectionRaw, representation, now)
				if err != nil || page.Content != want || page.Offset != int64(offset) || page.NextOffset != int64(offset+len(want)) || page.EndLine != last {
					t.Fatalf("start=%d bytes=%d: err=%v page=%+v", start, len(payload), err, page)
				}
			}
		}
	}
}

func FuzzPageTextParity(f *testing.F) {
	f.Add("", uint32(0), uint16(1))
	f.Add("first\n\n한글\nlast", uint32(7), uint16(2))
	f.Add(strings.Repeat("line\n", 3000), uint32(1500), uint16(100))
	f.Add(strings.Repeat("한", maximumPageSize), uint32(1), uint16(1))
	f.Fuzz(func(t *testing.T, payload string, inputOffset uint32, inputCount uint16) {
		if len(payload) > 4*maximumPageSize {
			t.Skip()
		}
		now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
		reference := dto.ArtifactRef{Encoding: dto.ArtifactEncodingUTF8}
		data, text := pageText{data: []byte(payload)}, pageText{text: payload}
		request := dto.ArtifactReadRequest{Offset: int64(inputOffset) % int64(len(payload)+2), Limit: minimumPageSize}
		bytePage, byteErr := readBytePage(reference, request, dto.ArtifactSectionStdout, data, now)
		textPage, textErr := readBytePage(reference, request, dto.ArtifactSectionStdout, text, now)
		if bytePage != textPage || !errors.Is(byteErr, textErr) {
			t.Fatalf("byte-page representation mismatch: %v / %v", byteErr, textErr)
		}
		request = dto.ArtifactReadRequest{StartLine: int(inputOffset % 4000), LineCount: int(inputCount % 502)}
		bytePage, byteErr = readLinePage(reference, request, dto.ArtifactSectionStdout, data, now)
		textPage, textErr = readLinePage(reference, request, dto.ArtifactSectionStdout, text, now)
		if bytePage != textPage || !errors.Is(byteErr, textErr) {
			t.Fatalf("line-page representation mismatch: %v / %v", byteErr, textErr)
		}
	})
}
