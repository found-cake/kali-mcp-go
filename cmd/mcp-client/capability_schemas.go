package main

import (
	"encoding/json"
	"fmt"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type toolInputSchemaCatalog map[string]json.RawMessage

func recordToolInputSchema(catalog toolInputSchemaCatalog, tool *mcp.Tool) error {
	encoded, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return fmt.Errorf("encode %s input schema: %w", tool.Name, err)
	}
	catalog[tool.Name] = encoded
	return nil
}

func attachCapabilityInputSchemas(result *dto.ScanCapabilitiesResult, catalog toolInputSchemaCatalog) error {
	for index := range result.Tools {
		schema, found := catalog[result.Tools[index].Tool]
		if !found {
			return fmt.Errorf("missing registered input schema for %s", result.Tools[index].Tool)
		}
		result.Tools[index].InputSchemaJSON = string(schema)
	}
	return nil
}
