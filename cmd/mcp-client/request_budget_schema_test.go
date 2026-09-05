package main

import "testing"

func TestScanSchemasExposeTimeoutRequestBudgetWithoutHardLimitClaim(t *testing.T) {
	t.Parallel()

	properties, ok := schemaProperties(listedToolByName(t, "ffuf_scan").InputSchema)
	if !ok {
		t.Fatal("ffuf_scan has an invalid input schema")
	}
	if _, found := properties["timeout_request_budget"]; !found {
		t.Fatal("timeout_request_budget is missing")
	}
	if _, found := properties["max_requests"]; found {
		t.Fatal("max_requests still implies a hard request limit")
	}
}
