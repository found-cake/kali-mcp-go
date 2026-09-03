package callid

import "testing"

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
