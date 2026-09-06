package main

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAsyncInputIsExposedOnlyForServerManagedStreamJobs(t *testing.T) {
	// Given: a streaming scanner, its synchronous counterpart, and a bounded HTTP request tool.
	tools := map[string]*mcp.Tool{}
	for _, tool := range listedTestTools(t) {
		tools[tool.Name] = tool
	}

	// When: their machine-readable input schemas are inspected.
	nucleiProperties, _ := schemaProperties(tools["nuclei_scan"].InputSchema)
	osvProperties, _ := schemaProperties(tools["osv_scan"].InputSchema)
	hydraStreamProperties, _ := schemaProperties(tools["hydra_attack_stream"].InputSchema)
	hydraPostProperties, _ := schemaProperties(tools["hydra_attack"].InputSchema)
	httpProperties, _ := schemaProperties(tools["http_request"].InputSchema)
	_, nucleiAsync := nucleiProperties["async"]
	_, osvAsync := osvProperties["async"]
	_, hydraStreamAsync := hydraStreamProperties["async"]
	_, hydraPostAsync := hydraPostProperties["async"]
	_, httpAsync := httpProperties["async"]

	// Then: only execution routes that can hand work to the job store expose async.
	if !nucleiAsync || !osvAsync || !hydraStreamAsync || hydraPostAsync || httpAsync {
		t.Fatalf("unexpected async schema exposure: nuclei=%t osv=%t hydra_stream=%t hydra_post=%t http=%t", nucleiAsync, osvAsync, hydraStreamAsync, hydraPostAsync, httpAsync)
	}
}
