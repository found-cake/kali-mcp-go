package dto

type ArtifactReadRequest struct {
	ArtifactID string `json:"artifact_id" jsonschema:"opaque result artifact ID returned by a scan"`
	Offset     int64  `json:"offset,omitempty" jsonschema:"UTF-8 byte offset returned by the previous page (default 0)"`
	Limit      int    `json:"limit,omitempty" jsonschema:"page size in bytes (default 16384, minimum 256, maximum 65536)"`
}

type ArtifactReadResult struct {
	ArtifactID string `json:"artifact_id"`
	Content    string `json:"content"`
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"next_offset"`
	HasMore    bool   `json:"has_more"`
	TotalBytes int64  `json:"total_bytes"`
}
