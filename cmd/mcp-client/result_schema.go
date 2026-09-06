package main

import "github.com/google/jsonschema-go/jsonschema"

func toolResultOutputSchema() *jsonschema.Schema {
	properties := map[string]*jsonschema.Schema{
		"call_id":               stringSchema(),
		"stdout":                stringSchema(),
		"stderr":                stringSchema(),
		"stdout_bytes":          integerSchema(),
		"stderr_bytes":          integerSchema(),
		"output_truncated":      booleanSchema(),
		"return_code":           integerSchema(),
		"success":               describedBooleanSchema("whether tool execution succeeded"),
		"timed_out":             booleanSchema(),
		"cancelled":             booleanSchema(),
		"partial_results":       booleanSchema(),
		"status":                enumSchema("completed", "failed", "timeout", "cancelled"),
		"execution_status":      describedEnumSchema("tool execution outcome", "succeeded", "failed", "timed_out", "cancelled"),
		"finding_status":        describedEnumSchema("finding outcome independent of execution status", "detected", "not_detected", "inconclusive", "unknown"),
		"finding_types":         stringArraySchema("service", "technology", "content", "vulnerability", "misconfiguration", "credential", "authentication"),
		"classification_reason": stringSchema(),
		"http_requests":         nullableSchema("integer"),
		"request_count_source":  enumSchema("measured", "parsed", "unknown"),
		"duration_ms":           integerSchema(),
		"failure":               nullableSchema("object"),
		"execution":             objectSchema(),
		"target":                nullableSchema("object"),
		"spa_baseline":          nullableSchema("object"),
		"false_positive_risk":   stringSchema(),
		"warnings":              arraySchema(),
		"artifacts":             nullableArraySchema(),
		"http_request":          nullableSchema("object"),
		"http_response":         nullableSchema("object"),
		"jwt_analysis":          nullableSchema("object"),
		"sqlmap_analysis":       nullableSchema("object"),
		"nuclei_preview":        nullableSchema("object"),
		"nuclei_runtime":        nullableSchema("object"),
		"discovered_paths":      nullableArraySchema(),
		"evidence":              nullableSchema("object"),
		"progress":              nullableSchema("object"),
	}
	return &jsonschema.Schema{
		Type:       "object",
		Properties: properties,
		Required: []string{
			"call_id", "stdout", "stderr", "stdout_bytes", "stderr_bytes", "output_truncated",
			"return_code", "success", "timed_out", "cancelled", "partial_results", "status",
			"execution_status", "finding_status", "http_requests", "request_count_source",
			"duration_ms", "failure", "execution", "target", "spa_baseline", "false_positive_risk", "artifacts",
		},
	}
}

func stringSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string"}
}

func integerSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "integer"}
}

func booleanSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "boolean"}
}

func describedBooleanSchema(description string) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "boolean", Description: description}
}

func objectSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "object"}
}

func arraySchema() *jsonschema.Schema {
	return &jsonschema.Schema{Types: []string{"array", "null"}, Items: &jsonschema.Schema{}}
}

func nullableArraySchema() *jsonschema.Schema {
	return arraySchema()
}

func nullableSchema(schemaType string) *jsonschema.Schema {
	return &jsonschema.Schema{Types: []string{schemaType, "null"}}
}

func enumSchema(values ...string) *jsonschema.Schema {
	return describedEnumSchema("", values...)
}

func describedEnumSchema(description string, values ...string) *jsonschema.Schema {
	enums := make([]any, 0, len(values))
	for _, value := range values {
		enums = append(enums, value)
	}
	return &jsonschema.Schema{Type: "string", Description: description, Enum: enums}
}

func stringArraySchema(values ...string) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "array", Items: enumSchema(values...)}
}
