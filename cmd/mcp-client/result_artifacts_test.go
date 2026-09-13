package main

import (
	"slices"
	"testing"
)

func TestResultArtifactReadSchemaExposesByteAndLineRanges(t *testing.T) {
	tool := listedToolByName(t, "result_artifact_read")
	properties, ok := schemaProperties(tool.InputSchema)
	if !ok {
		t.Fatal("result_artifact_read has an invalid input schema")
	}
	for _, field := range []string{"artifact_id", "section", "offset", "limit", "start_line", "line_count"} {
		if _, found := properties[field]; !found {
			t.Fatalf("result_artifact_read is missing %s", field)
		}
	}
	if got := schemaEnumValues(properties["section"]); !slices.Equal(got, []string{"raw", "stdout", "stderr"}) {
		t.Fatalf("unexpected artifact sections: %v", got)
	}
}
