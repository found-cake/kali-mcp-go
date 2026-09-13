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

type ArtifactSection string

const (
	ArtifactSectionRaw    ArtifactSection = "raw"
	ArtifactSectionStdout ArtifactSection = "stdout"
	ArtifactSectionStderr ArtifactSection = "stderr"
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
	ArtifactID string          `json:"artifact_id" jsonschema:"opaque artifact ID returned by the tool call that originally produced the evidence"`
	Section    ArtifactSection `json:"section,omitempty" jsonschema:"raw|stdout|stderr section to read (default raw); stdout and stderr require a tool-result-json artifact"`
	Offset     int64           `json:"offset,omitempty" jsonschema:"byte offset returned by the previous page (default 0); mutually exclusive with start_line and line_count"`
	Limit      int             `json:"limit,omitempty" jsonschema:"page size in bytes (default 16384, minimum 256, maximum 65536); mutually exclusive with start_line and line_count"`
	StartLine  int             `json:"start_line,omitempty" jsonschema:"1-based first line to read; enables line mode and is mutually exclusive with offset and limit"`
	LineCount  int             `json:"line_count,omitempty" jsonschema:"number of lines to read (default 100, maximum 500); enables line mode and is mutually exclusive with offset and limit"`
}

type ArtifactReadResult struct {
	CallID           string                 `json:"call_id" jsonschema:"call ID of this result_artifact_read operation"`
	ArtifactID       string                 `json:"artifact_id"`
	Content          string                 `json:"content"`
	Offset           int64                  `json:"offset"`
	NextOffset       int64                  `json:"next_offset"`
	HasMore          bool                   `json:"has_more"`
	TotalBytes       int64                  `json:"total_bytes"`
	Section          ArtifactSection        `json:"section"`
	StartLine        int                    `json:"start_line,omitempty"`
	EndLine          int                    `json:"end_line,omitempty"`
	NextLine         int                    `json:"next_line,omitempty"`
	TotalLines       int                    `json:"total_lines,omitempty"`
	LineTruncated    bool                   `json:"line_truncated,omitempty"`
	ExpiresAt        time.Time              `json:"expires_at"`
	ExpiresInSeconds int64                  `json:"expires_in_seconds"`
	ExpiringSoon     bool                   `json:"expiring_soon"`
	SourceCallID     string                 `json:"source_call_id" jsonschema:"call ID of the original tool operation that produced the artifact"`
	MediaType        string                 `json:"media_type"`
	Encoding         ArtifactEncoding       `json:"encoding"`
	RedactionState   ArtifactRedactionState `json:"redaction_state"`
	Relation         ArtifactRelation       `json:"relation"`
}
