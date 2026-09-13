package tools

import (
	"net/http"
	"reflect"
	"slices"
	"testing"
)

func TestRedactTextPreservesReplacementOrder(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
		secrets           []string
	}{
		{name: "none", input: "private", want: "private"},
		{name: "empty values", input: "private", secrets: []string{"", ""}, want: "private"},
		{name: "duplicates and overlap", input: "abcdef abc", secrets: []string{"abc", "", "abcdef", "abc"}, want: "[REDACTED] [REDACTED]"},
		{name: "replacement marker", input: "secret", secrets: []string{"RED", "secret"}, want: "[[REDACTED]ACTED]"},
		{name: "equal length", input: "abc", secrets: []string{"ab", "bc"}, want: "[REDACTED]c"},
		{name: "unicode", input: "한글 비밀", secrets: []string{"비밀"}, want: "한글 [REDACTED]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := slices.Clone(test.secrets)
			if got := RedactText(test.input, test.secrets); got != test.want {
				t.Fatalf("redacted=%q want=%q", got, test.want)
			}
			if !slices.Equal(test.secrets, original) {
				t.Fatal("caller secret slice was modified")
			}
		})
	}
}

func TestRedactHeadersPreservesCallerValues(t *testing.T) {
	headers := http.Header{"X-Values": {"abcdef", "abc", "ordinary"}, "X-Empty": nil}
	original := headers.Clone()
	got := RedactHeaders(headers, []string{"abc", "abcdef", "abc", ""})
	want := http.Header{"X-Values": {"[REDACTED]", "[REDACTED]", "ordinary"}, "X-Empty": nil}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(headers, original) {
		t.Fatalf("redacted=%v original=%v", got, headers)
	}
	got["X-Values"][0] = "changed"
	if !reflect.DeepEqual(headers, original) {
		t.Fatal("redacted headers alias caller storage")
	}
	if RedactHeaders(nil, nil) != nil {
		t.Fatal("nil headers changed to a non-nil map")
	}
}

func TestRedactorOwnsSecretSnapshot(t *testing.T) {
	secrets := []string{"abc", "abcdef"}
	redactor := NewRedactor(secrets)
	secrets[0], secrets[1] = "different", "changed"
	for range 8 {
		t.Run("shared snapshot", func(t *testing.T) {
			t.Parallel()
			if got := redactor.Text("abcdef abc"); got != "[REDACTED] [REDACTED]" {
				t.Fatalf("redactor snapshot changed: %q", got)
			}
		})
	}
	if got := (Redactor{}).Text("unchanged"); got != "unchanged" {
		t.Fatalf("zero-value redactor changed text: %q", got)
	}
}

func BenchmarkRedactHeaders(b *testing.B) {
	headers := http.Header{"X-Values": make([]string, 64)}
	for i := range headers["X-Values"] {
		headers["X-Values"][i] = "abcdef abc ordinary"
	}
	secrets := []string{"abc", "abcdef", "", "abc"}
	b.ReportAllocs()
	for b.Loop() {
		redacted := RedactHeaders(headers, secrets)
		if redacted.Get("X-Values") != "[REDACTED] [REDACTED] ordinary" {
			b.Fatal("unexpected redacted header")
		}
	}
}
