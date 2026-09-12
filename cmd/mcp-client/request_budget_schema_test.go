package main

import "testing"

func TestScanSchemasDoNotExposeTimeoutRequestBudget(t *testing.T) {
	t.Parallel()

	// Given: the public FFUF tool declaration.
	properties, ok := schemaProperties(listedToolByName(t, "ffuf_scan").InputSchema)
	if !ok {
		t.Fatal("ffuf_scan has an invalid input schema")
	}

	// When: callers inspect the available scan controls.
	_, found := properties["timeout_request_budget"]

	// Then: the server does not advertise an estimate as an execution control.
	if found {
		t.Fatal("timeout_request_budget still exposes server-side duration estimation")
	}
}
