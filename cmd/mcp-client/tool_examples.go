package main

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
)

var toolInputExamples = map[string]json.RawMessage{
	"browser_check":         json.RawMessage(`{"url":"https://host/app#route","headers":{"Cookie":"session=..."},"local_storage":{"access_token":"..."},"profile":"browser-xss-confirm"}`),
	"get_scan_capabilities": json.RawMessage(`{"tool_names":["nuclei_scan","feroxbuster_scan"]}`),
	"nmap_scan":             json.RawMessage(`{"target":"host","scan_type":"-sCV"}`),
	"nikto_scan":            json.RawMessage(`{"target":"https://host","request_timeout":10,"failure_limit":20,"profile":"web-discovery-low-rate"}`),
	"nuclei_scan":           json.RawMessage(`{"target":"https://host","severity":"medium,high,critical","max_host_errors":20,"request_timeout":10}`),
	"dalfox_scan":           json.RawMessage(`{"target":"https://host/?q=FUZZ","headers":{"Authorization":"Bearer ..."},"cookies":"session=...","profile":"browser-xss-confirm"}`),
	"result_artifact_read":  json.RawMessage(`{"artifact_id":"...","limit":65536}`),
	"retirejs_scan":         json.RawMessage(`{"url":"https://host/app","headers":{"Authorization":"Bearer ..."},"profile":"safe-recon"}`),
	"sqlmap_scan":           json.RawMessage(`{"url":"https://host/api/login","data":"{\"email\":\"test*\"}","content_type":"application/json","ignore_codes":"401","test_parameters":"email","true_status_code":200,"payload_prefix":"'))","payload_suffix":"-- ","profile":"sqli-verify-low-risk"}`),
}

func applyToolInputExample(name, description string, schema *jsonschema.Schema) string {
	example, found := toolInputExamples[name]
	if !found {
		return description
	}
	schema.Examples = []any{append(json.RawMessage(nil), example...)}
	return description + " Example input: " + string(example)
}
