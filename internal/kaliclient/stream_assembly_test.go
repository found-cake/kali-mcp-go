package kaliclient

import (
	"slices"
	"strings"
	"testing"
)

func TestJoinStreamLinesPreservesExactNewlines(t *testing.T) {
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
			original := slices.Clone(test.lines)
			if got := joinStreamLines(test.lines); got != test.want {
				t.Fatalf("joined=%q want=%q", got, test.want)
			}
			if !slices.Equal(test.lines, original) {
				t.Fatal("input lines changed")
			}
		})
	}
}

func TestBaseResultPreservesStderrBackingArray(t *testing.T) {
	backing := []string{"first", "second", "sentinel"}
	accumulator := streamAccumulator{stderr: backing[:2], finalError: "final"}
	result := accumulator.baseResult()
	if result.Stderr != "first\nsecond\nfinal\n" || backing[2] != "sentinel" || len(accumulator.stderr) != 2 {
		t.Fatalf("stderr=%q backing=%q", result.Stderr, backing)
	}
	if again := accumulator.baseResult(); again.Stderr != result.Stderr {
		t.Fatal("repeated formatting changed stderr")
	}
}

func BenchmarkJoinStreamLines(b *testing.B) {
	for _, test := range []struct {
		name  string
		count int
	}{
		{name: "empty"},
		{name: "one", count: 1},
		{name: "1000", count: 1000},
	} {
		b.Run(test.name, func(b *testing.B) {
			lines := make([]string, test.count)
			for i := range lines {
				lines[i] = strings.Repeat("x", 120)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if got := joinStreamLines(lines); len(got) != test.count*121 {
					b.Fatal("unexpected joined length")
				}
			}
		})
	}
}
