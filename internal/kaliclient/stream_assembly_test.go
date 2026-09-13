package kaliclient

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStreamCapturePreservesNormalizedLines(t *testing.T) {
	for _, test := range []struct {
		name  string
		lines []string
		want  string
	}{
		{name: "nil"},
		{name: "empty", lines: []string{}},
		{name: "blank", lines: []string{""}, want: "\n"},
		{name: "one", lines: []string{"line"}, want: "line\n"},
		{name: "blank entries", lines: []string{"", "한글", ""}, want: "\n한글\n\n"},
		{name: "embedded newlines", lines: []string{"a\nb", "c\n", "\r"}, want: "a\nb\nc\n\n\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var capture streamCapture
			for _, line := range test.lines {
				capture.retainLine(line, 0, dto.MaximumRetainedOutputBytes)
			}
			if got := capture.builder.String(); got != test.want {
				t.Fatalf("joined=%q want=%q", got, test.want)
			}
		})
	}
}

func TestBaseResultDoesNotMutateRetainedStderr(t *testing.T) {
	accumulator := streamAccumulator{finalError: "final"}
	for _, line := range []string{"first", "second"} {
		if err := accumulator.consume(dto.StreamEvent{Stream: "stderr", Line: line}); err != nil {
			t.Fatal(err)
		}
	}
	result := accumulator.baseResult()
	if result.Stderr != "first\nsecond\nfinal\n" || accumulator.stderr.builder.String() != "first\nsecond\n" {
		t.Fatalf("stderr=%q retained=%q", result.Stderr, accumulator.stderr.builder.String())
	}
	if again := accumulator.baseResult(); again.Stderr != result.Stderr {
		t.Fatal("repeated formatting changed stderr")
	}
}

func TestStreamAccumulatorBoundsOutputBeforeCompaction(t *testing.T) {
	// Given: a stream accumulator with room for two five-byte lines.
	accumulator := streamAccumulator{outputLimit: 10}

	// When: a third line exceeds the retention boundary.
	for _, event := range []dto.StreamEvent{
		{Stream: "stdout", Line: "1234"},
		{Stream: "stdout", Line: "5678"},
		{Stream: "stdout", Line: "x", ObservedBytes: 1},
	} {
		if err := accumulator.consume(event); err != nil {
			t.Fatal(err)
		}
	}
	result := accumulator.partialResult()

	// Then: the prefix remains available with accurate truncation and observed-byte metadata.
	if result.Stdout != "1234\n5678\n" || result.StdoutBytes != 11 || !result.StdoutTruncated || !result.OutputTruncated {
		t.Fatalf("unexpected bounded stream result: %+v", result)
	}
}

func BenchmarkStreamCapture(b *testing.B) {
	for _, test := range []struct {
		name  string
		count int
	}{
		{name: "empty"},
		{name: "one", count: 1},
		{name: "1000", count: 1000},
	} {
		b.Run(test.name, func(b *testing.B) {
			line := strings.Repeat("x", 120)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var capture streamCapture
				for range test.count {
					capture.retainLine(line, 0, dto.MaximumRetainedOutputBytes)
				}
				if got := capture.builder.Len(); got != test.count*121 {
					b.Fatal("unexpected joined length")
				}
			}
		})
	}
}
