package main

import "testing"

func TestBrowserAndRetireSchemasExposePerCallHeaders(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"browser_check", "retirejs_scan"} {
		properties, ok := schemaProperties(listedToolByName(t, name).InputSchema)
		if !ok {
			t.Fatalf("%s has an invalid input schema", name)
		}
		if _, found := properties["headers"]; !found {
			t.Fatalf("%s does not accept per-call headers", name)
		}
	}
}
