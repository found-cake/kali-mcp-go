package tools

import (
	"context"
	"net"
	"testing"
)

type staticIPResolver []net.IPAddr

func (r staticIPResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r, nil
}

func TestLoopbackHostDetectionRejectsDNSAliasResolvingToLoopback(t *testing.T) {
	// Given: a non-literal hostname whose DNS answer points at the local runtime.
	resolver := staticIPResolver{{IP: net.ParseIP("127.0.0.1")}}

	// When: the execution boundary classifies the hostname.
	loopback := isLoopbackHostWithResolver(context.Background(), resolver, "target.example")

	// Then: the alias is treated exactly like a literal loopback address.
	if !loopback {
		t.Fatal("DNS alias resolving to loopback bypassed target resolution")
	}
}
