package dto

type ArtifactReadRequest struct {
	ArtifactID string `json:"artifact_id" jsonschema:"opaque result artifact ID returned by a scan"`
}

type ArtifactReadResult struct {
	ArtifactID string `json:"artifact_id"`
	Content    string `json:"content"`
}
