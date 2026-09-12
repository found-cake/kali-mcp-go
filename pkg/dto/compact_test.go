package dto

import (
	"runtime"
	"strings"
	"testing"
)

func TestCompactUTF8PreservesLimits(t *testing.T) {
	for _, test := range []struct {
		name, value, want string
		limit             int
		truncated         bool
	}{
		{name: "unlimited", value: "a한b", limit: -1, want: "a한b"},
		{name: "empty", limit: 0},
		{name: "zero", value: "a한b", limit: 0, truncated: true},
		{name: "inside rune", value: "a한b", limit: 2, want: "a", truncated: true},
		{name: "rune boundary", value: "a한b", limit: 4, want: "a한", truncated: true},
		{name: "exact", value: "a한b", limit: 5, want: "a한b"},
		{name: "below limit", value: "a한b", limit: 6, want: "a한b"},
		{name: "invalid byte", value: "a\xffb", limit: 2, want: "a\xff", truncated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, truncated := compactUTF8(test.value, test.limit)
			if got != test.want || truncated != test.truncated {
				t.Fatalf("compacted=%q truncated=%v want=%q truncated=%v", got, truncated, test.want, test.truncated)
			}
		})
	}
}

func BenchmarkCompactRetainedHeap(b *testing.B) {
	retained := make([]ToolResult, 32)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	index := 0
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		retained[index%len(retained)] = (ToolResult{Stdout: strings.Repeat("x", 1<<20)}).Compact(1024)
		index++
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained-B")
	runtime.KeepAlive(retained)
}
