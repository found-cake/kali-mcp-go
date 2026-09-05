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
		"nmap_scan":            `{"target":"host","scan_type":"-sCV"}`,
		"nuclei_scan":          `{"target":"https://host","severity":"medium,high,critical"}`,
		"dalfox_scan":          `{"target":"https://host/?q=FUZZ"}`,
		"result_artifact_read": `{"artifact_id":"...","limit":65536}`,
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
