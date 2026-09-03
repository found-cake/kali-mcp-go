package targeting

import (
	"net"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func SchedulerKey(target string, provenance *dto.TargetProvenance) string {
	if origin, ok := Origin(target); ok {
		return origin
	}
	host := strings.Trim(strings.TrimSpace(target), "[]")
	port := 0
	if parsedHost, parsedPort, err := net.SplitHostPort(strings.TrimSpace(target)); err == nil {
		host = parsedHost
		port, _ = strconv.Atoi(parsedPort)
	}
	if provenance != nil && provenance.Port > 0 {
		port = provenance.Port
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
