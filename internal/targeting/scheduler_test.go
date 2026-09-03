package targeting

import (
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSchedulerKeyCanonicalizesOneService(t *testing.T) {
	t.Parallel()

	web := &dto.TargetProvenance{Port: 3000}
	if first, second := SchedulerKey("http://Example.test:3000/a", web), SchedulerKey("http://example.test:3000/b?q=1", web); first != second {
		t.Fatalf("same web origin has different scheduler keys: %q != %q", first, second)
	}
	network := &dto.TargetProvenance{Port: 3000}
	if got := SchedulerKey("192.0.2.10", network); got != "192.0.2.10:3000" {
		t.Fatalf("network scheduler key lost its port: %q", got)
	}
}
