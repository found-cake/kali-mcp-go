package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestResolveTargetRouteReportsReachableRuntimeCandidate(t *testing.T) {
	// Given: an authenticated API and a service inside the server runtime.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go acceptResolverConnections(listener)
	port := listener.Addr().(*net.TCPAddr).Port
	app := newApp("secret-token", false, defaultMaxConcurrentExecutions, t.Logf)
	body, err := json.Marshal(dto.ResolveTargetRequest{
		Target:                     fmt.Sprintf("127.0.0.1:%d", port),
		ConnectTimeoutMilliseconds: 100,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, "/api/tools/resolve-target", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("Content-Type", "application/json")

	// When: the resolver endpoint is called through the registered route.
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("resolve target request: %v", err)
	}
	defer response.Body.Close()
	var result dto.TargetResolutionResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Then: the API reports the original runtime target as reachable.
	if response.StatusCode != http.StatusOK || len(result.Candidates) == 0 || !result.Candidates[0].Reachable {
		t.Fatalf("unexpected resolver response: status=%d result=%+v", response.StatusCode, result)
	}
}

func acceptResolverConnections(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.Close()
	}
}
