package targeting

import (
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSQLMapAbsoluteRequestTargetMustMatchHostWithoutContext(t *testing.T) {
	t.Parallel()

	request := dto.SQLMapRequest{RawRequest: "GET http://198.51.100.20:3000/ HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n"}
	target, err := sqlMapRequestTarget(request)
	if err == nil || target != "" || !strings.Contains(err.Error(), "Host") {
		t.Fatalf("absolute request target bypassed Host destination: target=%q err=%v", target, err)
	}
}
