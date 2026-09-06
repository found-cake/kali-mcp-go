package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestToolInputExamplesAreExposedInSchemaAndDescription(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"browser_check":        `{"url":"https://host/app#route","headers":{"Cookie":"session=..."},"profile":"browser-xss-confirm"}`,
		"nmap_scan":            `{"target":"host","scan_type":"-sCV"}`,
		"nikto_scan":           `{"target":"https://host","request_timeout":10,"failure_limit":20,"profile":"web-discovery-low-rate"}`,
		"nuclei_scan":          `{"target":"https://host","severity":"medium,high,critical","max_host_errors":20,"request_timeout":10}`,
		"dalfox_scan":          `{"target":"https://host/?q=FUZZ","request_timeout":10,"scan_timeout":60,"profile":"browser-xss-confirm"}`,
		"result_artifact_read": `{"artifact_id":"...","limit":65536}`,
		"retirejs_scan":        `{"url":"https://host/app","headers":{"Authorization":"Bearer ..."},"profile":"safe-recon"}`,
		"sqlmap_scan":          `{"url":"https://host/search?q=1","test_parameters":"q","abort_codes":"500,503","profile":"sqli-verify-low-risk"}`,
	}

	for name, encoded := range want {
		t.Run(name, func(t *testing.T) {
			tool := listedToolByName(t, name)
			schema, ok := tool.InputSchema.(map[string]any)
			if !ok {
				t.Fatalf("input schema type = %T", tool.InputSchema)
			}
			examples, ok := schema["examples"].([]any)
			if !ok || len(examples) != 1 {
				t.Fatalf("schema examples = %#v", schema["examples"])
			}
			var expected map[string]any
			if err := json.Unmarshal([]byte(encoded), &expected); err != nil {
				t.Fatalf("decode expected example: %v", err)
			}
			if !reflect.DeepEqual(examples[0], expected) {
				t.Fatalf("schema example = %#v, want %#v", examples[0], expected)
			}
			if !strings.Contains(tool.Description, encoded) {
				t.Fatalf("description does not expose compact example %s", encoded)
			}
		})
	}
}
