package main

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
)

var toolInputExamples = map[string]json.RawMessage{
	"browser_check":        json.RawMessage(`{"url":"https://host/app#route","headers":{"Cookie":"session=..."},"profile":"browser-xss-confirm"}`),
	"nmap_scan":            json.RawMessage(`{"target":"host","scan_type":"-sCV"}`),
	"nuclei_scan":          json.RawMessage(`{"target":"https://host","severity":"medium,high,critical"}`),
	"dalfox_scan":          json.RawMessage(`{"target":"https://host/?q=FUZZ"}`),
	"result_artifact_read": json.RawMessage(`{"artifact_id":"...","limit":65536}`),
	"retirejs_scan":        json.RawMessage(`{"url":"https://host/app","headers":{"Authorization":"Bearer ..."},"profile":"safe-recon"}`),
	"sqlmap_scan":          json.RawMessage(`{"url":"https://host/search?q=1","test_parameters":"q","abort_codes":"500,503","profile":"sqli-verify-low-risk"}`),
}

func applyToolInputExample(name, description string, schema *jsonschema.Schema) string {
	example, found := toolInputExamples[name]
	if !found {
		return description
	}
	schema.Examples = []any{append(json.RawMessage(nil), example...)}
	return description + " Example input: " + string(example)
}
