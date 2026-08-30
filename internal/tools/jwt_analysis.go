package tools

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func AnalyzeJWTStructure(token string) dto.JWTAnalysisMetadata {
	parts := strings.Split(strings.TrimSpace(token), ".")
	metadata := dto.JWTAnalysisMetadata{SegmentCount: len(parts)}
	switch len(parts) {
	case 3:
	case 5:
		metadata.ParseStatus = dto.JWTUnsupported
		metadata.FailureStage = dto.JWTFailureSegments
		return metadata
	default:
		metadata.ParseStatus = dto.JWTMalformed
		metadata.FailureStage = dto.JWTFailureSegments
		return metadata
	}
	headerBytes, ok := decodeJWTPart(parts[0])
	if !ok {
		metadata.ParseStatus = dto.JWTMalformed
		metadata.FailureStage = dto.JWTFailureHeaderBase64
		return metadata
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		metadata.ParseStatus = dto.JWTMalformed
		metadata.FailureStage = dto.JWTFailureHeaderJSON
		return metadata
	}
	payloadBytes, ok := decodeJWTPart(parts[1])
	if !ok {
		metadata.ParseStatus = dto.JWTMalformed
		metadata.FailureStage = dto.JWTFailurePayloadBase64
		return metadata
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		metadata.ParseStatus = dto.JWTMalformed
		metadata.FailureStage = dto.JWTFailurePayloadJSON
		return metadata
	}
	metadata.ParseStatus = dto.JWTParsed
	metadata.Algorithm = header.Algorithm
	metadata.Type = header.Type
	metadata.ClaimNames = make([]string, 0, len(claims))
	for name := range claims {
		metadata.ClaimNames = append(metadata.ClaimNames, name)
	}
	slices.Sort(metadata.ClaimNames)
	return metadata
}

func decodeJWTPart(value string) ([]byte, bool) {
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return payload, true
	}
	payload, err = base64.URLEncoding.DecodeString(value)
	return payload, err == nil
}
