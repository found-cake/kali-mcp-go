package dto

import "encoding/json"

type inlineResultAssessment struct {
	Status                 RunStatus       `json:"status"`
	ExecutionStatus        ExecutionStatus `json:"execution_status"`
	FindingStatus          FindingStatus   `json:"finding_status"`
	FindingTypes           []FindingType   `json:"finding_types,omitempty"`
	ClassificationReason   string          `json:"classification_reason,omitempty"`
	OutputTruncated        bool            `json:"output_truncated"`
	StdoutTruncated        bool            `json:"stdout_truncated"`
	StderrTruncated        bool            `json:"stderr_truncated"`
	FindingOutputTruncated bool            `json:"finding_output_truncated"`
	ArtifactComplete       bool            `json:"artifact_complete"`
}

type inlineHTTPResponseSummary struct {
	StatusCode             int      `json:"status_code"`
	FinalURL               string   `json:"final_url"`
	BodyBytes              int      `json:"body_bytes"`
	BodyTruncated          bool     `json:"body_truncated"`
	BodySHA256             string   `json:"body_sha256,omitempty"`
	JSONKeys               []string `json:"json_keys,omitempty"`
	Location               string   `json:"location,omitempty"`
	StackTraceSuspected    bool     `json:"stack_trace_suspected"`
	SensitiveDataSuspected bool     `json:"sensitive_data_suspected"`
}

type inlineResultSummary struct {
	Assessment     inlineResultAssessment     `json:"assessment"`
	HTTPResponse   *inlineHTTPResponseSummary `json:"http_response,omitempty"`
	SQLMapAnalysis *SQLMapAnalysis            `json:"sqlmap_analysis,omitempty"`
	JWTStructure   *JWTAnalysisMetadata       `json:"jwt_structure,omitempty"`
	NucleiPreview  *NucleiPreviewMetadata     `json:"nuclei_preview,omitempty"`
}

func (r ToolResult) inlineStructuredSummary() (string, error) {
	if r.HTTPResponse == nil && r.SQLMapAnalysis == nil && r.JWTAnalysis == nil && r.NucleiPreview == nil {
		return "", nil
	}
	summary := inlineResultSummary{
		Assessment: inlineResultAssessment{
			Status: r.Status, ExecutionStatus: r.ExecutionStatus, FindingStatus: r.FindingStatus,
			FindingTypes: r.FindingTypes, ClassificationReason: r.ClassificationReason,
			OutputTruncated: r.OutputTruncated, StdoutTruncated: r.StdoutTruncated,
			StderrTruncated: r.StderrTruncated, FindingOutputTruncated: r.FindingOutputTruncated,
			ArtifactComplete: r.ArtifactComplete,
		},
		SQLMapAnalysis: r.SQLMapAnalysis,
		JWTStructure:   r.JWTAnalysis,
		NucleiPreview:  r.NucleiPreview,
	}
	if r.HTTPResponse != nil {
		httpSummary := inlineHTTPResponseSummary{
			StatusCode: r.HTTPResponse.StatusCode, FinalURL: r.HTTPResponse.FinalURL,
			BodyBytes: r.HTTPResponse.BodyBytes, BodyTruncated: r.HTTPResponse.BodyTruncated,
		}
		if r.HTTPResponse.Summary != nil {
			httpSummary.BodySHA256 = r.HTTPResponse.Summary.BodySHA256
			httpSummary.JSONKeys = r.HTTPResponse.Summary.JSONKeys
			httpSummary.Location = r.HTTPResponse.Summary.Location
			httpSummary.StackTraceSuspected = r.HTTPResponse.Summary.StackTraceSuspected
			httpSummary.SensitiveDataSuspected = r.HTTPResponse.Summary.SensitiveDataSuspected
		}
		summary.HTTPResponse = &httpSummary
	}
	encoded, err := json.Marshal(summary)
	return string(encoded), err
}
