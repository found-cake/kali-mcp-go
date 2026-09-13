package targeting

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSchedulerKeyCanonicalizesOneService(t *testing.T) {
	t.Parallel()

	web := &dto.TargetProvenance{Port: 3000}
	if first, second := SchedulerKey("http://Example.test:3000/a", web), SchedulerKey("http://example.test:3000/b?q=1", web); first != second || first != "example.test:3000" {
		t.Fatalf("same web origin has different scheduler keys: %q != %q", first, second)
	}
	network := &dto.TargetProvenance{Port: 3000}
	if got := SchedulerKey("192.0.2.10", network); got != "192.0.2.10:3000" {
		t.Fatalf("network scheduler key lost its port: %q", got)
	}
}

func TestSchedulerKeySharesCapacityAcrossToolTargetForms(t *testing.T) {
	t.Parallel()

	provenance := &dto.TargetProvenance{
		Original: "http://127.0.0.1:3000/", Selected: "http://192.168.65.254:3000/",
		Verified: true, Port: 3000,
	}
	want := "127.0.0.1:3000"
	for _, target := range []string{
		"http://192.168.65.254:3000/path",
		"192.168.65.254",
		"192.168.65.254:3000",
	} {
		if got := SchedulerKey(target, provenance); got != want {
			t.Fatalf("target %q received scheduler key %q, want %q", target, got, want)
		}
	}
}
