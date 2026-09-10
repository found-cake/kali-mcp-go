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
		"browser_check":         `{"url":"https://host/app#route","headers":{"Cookie":"session=..."},"local_storage":{"access_token":"..."},"profile":"browser-xss-confirm"}`,
		"get_scan_capabilities": `{"tool_names":["nuclei_scan","feroxbuster_scan"]}`,
		"nmap_scan":             `{"target":"host","scan_type":"-sCV"}`,
		"nikto_scan":            `{"target":"https://host","request_timeout":10,"failure_limit":20,"profile":"web-discovery-low-rate"}`,
		"nuclei_scan":           `{"target":"https://host","severity":"medium,high,critical","max_host_errors":20,"request_timeout":10}`,
		"dalfox_scan":           `{"target":"https://host/?q=FUZZ","headers":{"Authorization":"Bearer ..."},"cookies":"session=...","profile":"browser-xss-confirm"}`,
		"result_artifact_read":  `{"artifact_id":"...","limit":65536}`,
		"retirejs_scan":         `{"url":"https://host/app","headers":{"Authorization":"Bearer ..."},"profile":"safe-recon"}`,
		"sqlmap_scan":           `{"url":"https://host/api/login","data":"{\"email\":\"test*\"}","content_type":"application/json","ignore_codes":"401","test_parameters":"email","true_status_code":200,"payload_prefix":"'))","payload_suffix":"-- ","profile":"sqli-verify-low-risk"}`,
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
