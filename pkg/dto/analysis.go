package dto

type JWTParseStatus string

const (
	JWTParsed      JWTParseStatus = "parsed"
	JWTMalformed   JWTParseStatus = "malformed"
	JWTUnsupported JWTParseStatus = "unsupported"
)

type JWTFailureStage string

const (
	JWTFailureSegments      JWTFailureStage = "segments"
	JWTFailureHeaderBase64  JWTFailureStage = "header_base64"
	JWTFailureHeaderJSON    JWTFailureStage = "header_json"
	JWTFailurePayloadBase64 JWTFailureStage = "payload_base64"
	JWTFailurePayloadJSON   JWTFailureStage = "payload_json"
)

type JWTAnalysisMetadata struct {
	ParseStatus  JWTParseStatus  `json:"parse_status"`
	FailureStage JWTFailureStage `json:"failure_stage,omitempty"`
	SegmentCount int             `json:"segment_count"`
	Algorithm    string          `json:"alg,omitempty"`
	Type         string          `json:"typ,omitempty"`
	ClaimNames   []string        `json:"claim_names,omitempty"`
}
