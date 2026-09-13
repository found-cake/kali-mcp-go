package callid

import (
	"strings"
	"testing"
)

func TestNewProducesValidUniqueIdentifiers(t *testing.T) {
	first, err := New()
	if err != nil {
		t.Fatalf("new first call ID: %v", err)
	}
	second, err := New()
	if err != nil {
		t.Fatalf("new second call ID: %v", err)
	}
	if !Valid(first) || !Valid(second) || first == second {
		t.Fatalf("invalid or duplicate call IDs: first=%q second=%q", first, second)
	}
}

func TestValidRejectsMalformedIdentifiers(t *testing.T) {
	for _, value := range []string{"", "call_short", "other_0123456789abcdef0123456789abcdef", "call_0123456789abcdef0123456789abcdeg"} {
		if Valid(value) {
			t.Fatalf("malformed call ID accepted: %q", value)
		}
	}
}

func TestValidAcceptsOnlyHexBytesAtEveryPosition(t *testing.T) {
	value := []byte("call_0123456789abcdefABCDEF0123456789")
	for position := len(prefix); position < len(value); position++ {
		original := value[position]
		for candidate := 0; candidate < 256; candidate++ {
			value[position] = byte(candidate)
			want := strings.ContainsRune("0123456789abcdefABCDEF", rune(candidate))
			if got := Valid(string(value)); got != want {
				t.Fatalf("position=%d byte=%d valid=%v want=%v", position, candidate, got, want)
			}
		}
		value[position] = original
	}
}

func BenchmarkValid(b *testing.B) {
	value := "call_0123456789abcdefABCDEF0123456789"
	b.ReportAllocs()
	for b.Loop() {
		if !Valid(value) {
			b.Fatal("valid ID rejected")
		}
	}
}
