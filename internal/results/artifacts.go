package results

import (
	"encoding/json"
	"time"

	artifactstore "github.com/found-cake/kali-mcp-go/internal/artifacts"
	"github.com/found-cake/kali-mcp-go/internal/executor"
	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	mediaTypeApplicationJSON = "application/json"
	mediaTypeTextHTML        = "text/html"
)

func attachResultArtifact(store *artifactstore.Store, result *executor.Result, state dto.ArtifactRedactionState) {
	if store == nil || result == nil {
		return
	}
	rebuildEvidenceManifest(result)
	payload, err := json.MarshalIndent(ToToolResult(result), "", "  ")
	if err != nil {
		result.Warnings = append(result.Warnings, "result artifact unavailable: encode artifact: "+err.Error())
		return
	}
	artifact, err := store.Save(artifactstore.Content{
		Kind: "tool-result-json", MediaType: mediaTypeApplicationJSON,
		Encoding: dto.ArtifactEncodingUTF8, RedactionState: state,
		SourceCallID: result.CallID, Relation: dto.ArtifactRelationToolResult, Payload: payload,
	}, time.Now().UTC())
	if err != nil {
		result.Warnings = append(result.Warnings, "result artifact unavailable: "+err.Error())
		return
	}
	result.Artifacts = append(result.Artifacts, artifact)
	rebuildEvidenceManifest(result)
}

func rebuildEvidenceManifest(result *executor.Result) {
	if result == nil || len(result.Artifacts) == 0 {
		return
	}
	manifest := &dto.EvidenceManifest{GroupID: result.CallID, Artifacts: make([]dto.EvidenceArtifact, 0, len(result.Artifacts))}
	for _, artifact := range result.Artifacts {
		manifest.Artifacts = append(manifest.Artifacts, dto.EvidenceArtifact{ID: artifact.ID, Kind: artifact.Kind, Relation: artifact.Relation})
		if artifact.Relation == dto.ArtifactRelationToolResult {
			manifest.PrimaryArtifactID = artifact.ID
		}
	}
	result.Evidence = manifest
}
