package main

import "testing"

func TestAuthenticatedToolSchemasExposePerCallHeaders(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"browser_check", "dalfox_scan", "retirejs_scan"} {
		properties, ok := schemaProperties(listedToolByName(t, name).InputSchema)
		if !ok {
			t.Fatalf("%s has an invalid input schema", name)
		}
		if _, found := properties["headers"]; !found {
			t.Fatalf("%s does not accept per-call headers", name)
		}
	}

	dalfoxProperties, _ := schemaProperties(listedToolByName(t, "dalfox_scan").InputSchema)
	if _, found := dalfoxProperties["cookies"]; !found {
		t.Fatal("dalfox_scan does not accept per-call cookies")
	}
}
