package tools

import (
	"encoding/base64"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestAnalyzeJWTStructureReportsSafeParsedMetadata(t *testing.T) {
	// Given: a valid signed-token shape containing header and claim values.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"customer-1","role":"admin"}`))
	token := header + "." + payload + ".signature"

	// When: the token structure is analyzed without invoking jwt_tool.
	metadata := AnalyzeJWTStructure(token)

	// Then: only structural fields and claim names are retained.
	if metadata.ParseStatus != dto.JWTParsed || metadata.Algorithm != "HS256" || metadata.Type != "JWT" || len(metadata.ClaimNames) != 2 {
		t.Fatalf("unexpected JWT metadata: %+v", metadata)
	}
}

func TestAnalyzeJWTStructureReportsPayloadFailureStage(t *testing.T) {
	// Given: a three-segment token whose payload is not valid JSON.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not-json`))

	// When: the malformed structure is analyzed.
	metadata := AnalyzeJWTStructure(header + "." + payload + ".")

	// Then: callers can distinguish payload parsing failure from tool execution failure.
	if metadata.ParseStatus != dto.JWTMalformed || metadata.FailureStage != dto.JWTFailurePayloadJSON {
		t.Fatalf("unexpected JWT failure metadata: %+v", metadata)
	}
}
