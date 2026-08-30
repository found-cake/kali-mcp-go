package dto

import "time"

type ArtifactEncoding string

const (
	ArtifactEncodingUTF8   ArtifactEncoding = "utf-8"
	ArtifactEncodingBase64 ArtifactEncoding = "base64"
)

type ArtifactRedactionState string

const (
	ArtifactRedacted            ArtifactRedactionState = "redacted"
	ArtifactSensitiveUnredacted ArtifactRedactionState = "sensitive_unredacted"
)

type ArtifactRelation string

const (
	ArtifactRelationToolResult        ArtifactRelation = "tool_result"
	ArtifactRelationBrowserNetwork    ArtifactRelation = "browser_network"
	ArtifactRelationBrowserScreenshot ArtifactRelation = "browser_screenshot"
	ArtifactRelationBrowserDOM        ArtifactRelation = "browser_dom"
)

type ArtifactRef struct {
	ID             string                 `json:"id"`
	Kind           string                 `json:"kind"`
	Location       string                 `json:"location"`
	ExpiresAt      time.Time              `json:"expires_at"`
	SourceCallID   string                 `json:"source_call_id"`
	MediaType      string                 `json:"media_type"`
	Encoding       ArtifactEncoding       `json:"encoding"`
	RedactionState ArtifactRedactionState `json:"redaction_state"`
	Relation       ArtifactRelation       `json:"relation"`
}

type EvidenceArtifact struct {
	ID       string           `json:"id"`
	Kind     string           `json:"kind"`
	Relation ArtifactRelation `json:"relation"`
}

type EvidenceManifest struct {
	GroupID           string             `json:"group_id"`
	PrimaryArtifactID string             `json:"primary_artifact_id,omitempty"`
	Artifacts         []EvidenceArtifact `json:"artifacts"`
}

type ArtifactReadRequest struct {
	ArtifactID string `json:"artifact_id" jsonschema:"opaque result artifact ID returned by a scan"`
	Offset     int64  `json:"offset,omitempty" jsonschema:"UTF-8 byte offset returned by the previous page (default 0)"`
	Limit      int    `json:"limit,omitempty" jsonschema:"page size in bytes (default 16384, minimum 256, maximum 65536)"`
}

type ArtifactReadResult struct {
	CallID           string                 `json:"call_id"`
	ArtifactID       string                 `json:"artifact_id"`
	Content          string                 `json:"content"`
	Offset           int64                  `json:"offset"`
	NextOffset       int64                  `json:"next_offset"`
	HasMore          bool                   `json:"has_more"`
	TotalBytes       int64                  `json:"total_bytes"`
	ExpiresAt        time.Time              `json:"expires_at"`
	ExpiresInSeconds int64                  `json:"expires_in_seconds"`
	ExpiringSoon     bool                   `json:"expiring_soon"`
	SourceCallID     string                 `json:"source_call_id"`
	MediaType        string                 `json:"media_type"`
	Encoding         ArtifactEncoding       `json:"encoding"`
	RedactionState   ArtifactRedactionState `json:"redaction_state"`
	Relation         ArtifactRelation       `json:"relation"`
}
