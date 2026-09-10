package results

import (
	"context"
	"slices"
	"testing"

	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestProtectStreamPreservesMetadataAndRedactsEveryLine(t *testing.T) {
	input := make(chan executor.Line, 3)
	for _, stream := range []string{"stdout", "stderr", "stdout"} {
		input <- executor.Line{Stream: stream, Text: "abcdef abc"}
	}
	close(input)
	request := dto.CommandRequest{RedactValues: []string{"abc", "abcdef", "abc", ""}}
	output := ProtectStream(context.Background(), input, request)
	var streams []string
	for line := range output {
		if line.Text != "[REDACTED] [REDACTED]" {
			t.Fatalf("unexpected protected line: %+v", line)
		}
		streams = append(streams, line.Stream)
	}
	if !slices.Equal(streams, []string{"stdout", "stderr", "stdout"}) {
		t.Fatalf("stream metadata/order changed: %v", streams)
	}
}

func BenchmarkProtectRedaction(b *testing.B) {
	values := make([]string, 64)
	for index := range values {
		values[index] = "abcdef abc ordinary"
	}
	request := dto.CommandRequest{RedactValues: []string{"abc", "abcdef", "", "abc"}}
	b.ReportAllocs()
	for b.Loop() {
		result := &executor.Result{Stdout: "abcdef abc", ArgvRedacted: slices.Clone(values)}
		Protect(nil, result, request)
		if result.Stdout != "[REDACTED] [REDACTED]" {
			b.Fatal("unexpected protected output")
		}
	}
}
