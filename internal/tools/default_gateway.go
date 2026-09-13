package tools

import (
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

func defaultGateway() string {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		gatewayBytes, err := hex.DecodeString(fields[2])
		if err != nil || len(gatewayBytes) != net.IPv4len {
			continue
		}
		return net.IPv4(gatewayBytes[3], gatewayBytes[2], gatewayBytes[1], gatewayBytes[0]).String()
	}
	return ""
}
