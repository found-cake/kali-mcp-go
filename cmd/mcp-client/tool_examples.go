package main

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
)

var toolInputExamples = map[string]json.RawMessage{
	"nmap_scan":            json.RawMessage(`{"target":"host","scan_type":"-sCV"}`),
	"nuclei_scan":          json.RawMessage(`{"target":"https://host","severity":"medium,high,critical"}`),
	"dalfox_scan":          json.RawMessage(`{"target":"https://host/?q=FUZZ"}`),
	"result_artifact_read": json.RawMessage(`{"artifact_id":"...","limit":65536}`),
}

func applyToolInputExample(name, description string, schema *jsonschema.Schema) string {
	example, found := toolInputExamples[name]
	if !found {
		return description
	}
	schema.Examples = []any{append(json.RawMessage(nil), example...)}
	return description + " Example input: " + string(example)
}
