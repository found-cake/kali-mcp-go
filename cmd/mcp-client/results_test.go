package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestClassifyToolResultSeparatesFindingsFromExecution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tool        string
		in          dto.ToolResult
		exec        dto.ExecutionStatus
		find        dto.FindingStatus
		failureCode string
	}{
		{name: "sqlmap finding", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "Parameter: name (JSON) is vulnerable"}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "sqlmap clean", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "all tested parameters do not appear to be injectable"}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "sqlmap differential negative", tool: "sqlmap_scan", in: dto.ToolResult{Success: true, Stdout: "all tested parameters do not appear to be injectable", SQLMapAnalysis: &dto.SQLMapAnalysis{ManualVerificationRecommended: true}}, exec: dto.ExecutionSucceeded, find: dto.FindingsInconclusive},
		{name: "tool failure", tool: "sqlmap_scan", in: dto.ToolResult{ReturnCode: 1, Stderr: "unable to connect"}, exec: dto.ExecutionFailed, find: dto.FindingsUnknown},
		{name: "partial failure", tool: "sqlmap_scan", in: dto.ToolResult{ReturnCode: 1, Stdout: "testing parameter id", PartialResults: true}, exec: dto.ExecutionFailed, find: dto.FindingsInconclusive},
		{name: "timeout", tool: "nikto_scan", in: dto.ToolResult{TimedOut: true, PartialResults: true}, exec: dto.ExecutionTimedOut, find: dto.FindingsInconclusive},
		{name: "cancelled", tool: "nuclei_scan", in: dto.ToolResult{Cancelled: true}, exec: dto.ExecutionCancelled, find: dto.FindingsInconclusive},
		{name: "whatweb internal error", tool: "whatweb_scan", in: dto.ToolResult{Success: true, Stdout: "ERROR Opening: target"}, exec: dto.ExecutionFailed, find: dto.FindingsInconclusive},
		{name: "gobuster clean banner", tool: "gobuster_scan", in: dto.ToolResult{Success: true, Stdout: "Gobuster v3.8.2\nStarting gobuster\nFinished"}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "gobuster finding", tool: "gobuster_scan", in: dto.ToolResult{Success: true, Stdout: "/admin (Status: 200) [Size: 123]"}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "gobuster fuzz finding", tool: "gobuster_scan", in: dto.ToolResult{Success: true, Stdout: "[Status=200] [Length=28] [Word=robots.txt] http://example.test/robots.txt"}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "dalfox clean JSON", tool: "dalfox_scan", in: dto.ToolResult{Success: true, Stdout: `{"findings":[],"meta":{"findings_count":0}}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "browser invalid JSON", tool: "browser_check", in: dto.ToolResult{Success: true, Stdout: `not-json`}, exec: dto.ExecutionFailed, find: dto.FindingsInconclusive, failureCode: "output_parse_failed"},
		{name: "retire clean JSON", tool: "retirejs_scan", in: dto.ToolResult{Success: true, Stdout: `{"version":"5.7.0","data":[]}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "osv finding exit one", tool: "osv_scan", in: dto.ToolResult{ReturnCode: 1, Stdout: `{"results":[{"packages":[]}]}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsDetected},
		{name: "osv clean JSON", tool: "osv_scan", in: dto.ToolResult{Success: true, Stdout: `{"results":[]}`}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
		{name: "wpscan non wordpress target", tool: "wpscan_analyze", in: dto.ToolResult{ReturnCode: 4, Stdout: "Scan Aborted: The remote website is up, but does not seem to be running WordPress.", PartialResults: true, Failure: &dto.FailureInfo{Code: "nonzero_exit"}}, exec: dto.ExecutionSucceeded, find: dto.FindingsNotDetected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyToolResult(test.tool, test.in)
			if got.ExecutionStatus != test.exec || got.FindingStatus != test.find {
				t.Fatalf("classification mismatch: %+v", got)
			}
			if got.Success != (got.ExecutionStatus == dto.ExecutionSucceeded) {
				t.Fatalf("success disagrees with execution status: %+v", got)
			}
			if got.ExecutionStatus != dto.ExecutionSucceeded && got.Failure == nil {
				t.Fatalf("expected structured failure metadata: %+v", got)
			}
			if got.ExecutionStatus == dto.ExecutionSucceeded && got.Failure != nil {
				t.Fatalf("successful execution retained failure metadata: %+v", got)
			}
			if got.ExecutionStatus == dto.ExecutionSucceeded && got.PartialResults {
				t.Fatalf("completed execution retained partial-result status: %+v", got)
			}
			if got.ClassificationReason == "" {
				t.Fatalf("expected a machine-readable classification reason: %+v", got)
			}
			if test.failureCode != "" && (got.Failure == nil || got.Failure.Code != test.failureCode) {
				t.Fatalf("unexpected failure code: %+v", got.Failure)
			}
		})
	}
}

func TestTextResultReturnsStructuredContentAndMarksFailure(t *testing.T) {
	t.Parallel()

	input := &dto.ToolResult{ReturnCode: 2, Stderr: "execution failed"}
	callResult, structured, err := textResult("nmap_scan", input, nil)
	if err != nil {
		t.Fatalf("text result: %v", err)
	}
	if !callResult.IsError {
		t.Fatal("expected failed tool call to be marked as MCP error")
	}
	if structured.ExecutionStatus != dto.ExecutionFailed {
		t.Fatalf("expected structured failed status, got %+v", structured)
	}
}

func TestClassifyNiktoResultMarksInternalMaxTimeAsPartialTimeout(t *testing.T) {
	// Given: Nikto exited zero after its own maximum execution time stopped a scan with findings.
	input := dto.ToolResult{
		ReturnCode: 0,
		Stdout: "+ ERROR: Host maximum execution time of 2 seconds reached\n" +
			"+ Scan terminated: 0 errors and 1 item reported on the remote host\n",
	}

	// When: the MCP boundary classifies the tool result.
	result := classifyToolResult("nikto_scan", input)

	// Then: execution remains incomplete while the reported finding is preserved independently.
	if result.ExecutionStatus != dto.ExecutionTimedOut || !result.TimedOut || !result.PartialResults || result.FindingStatus != dto.FindingsDetected || result.ClassificationReason != "nikto_partial_finding_reported" {
		t.Fatalf("unexpected Nikto internal timeout classification: %+v", result)
	}
}

func TestClassifyNiktoTimeoutWithoutReportedItemsIsInconclusive(t *testing.T) {
	t.Parallel()

	result := classifyToolResult("nikto_scan", dto.ToolResult{
		ReturnCode: -1,
		TimedOut:   true,
		Stdout:     "+ 0 item(s) reported on the remote host\n",
	})

	if result.ExecutionStatus != dto.ExecutionTimedOut || result.FindingStatus != dto.FindingsInconclusive {
		t.Fatalf("unexpected Nikto timeout classification: %+v", result)
	}
}

func TestClassifyNiktoResultDoesNotInferTimeoutFromOrdinaryTimingText(t *testing.T) {
	// Given: a completed Nikto result that mentions time without an internal termination signature.
	input := dto.ToolResult{ReturnCode: 0, Stdout: "+ 0 item(s) reported\n+ End Time: 2026-09-03\n"}

	// When: the MCP boundary classifies the tool result.
	result := classifyToolResult("nikto_scan", input)

	// Then: the completed scan retains its normal clean classification.
	if result.ExecutionStatus != dto.ExecutionSucceeded || result.PartialResults || result.FindingStatus != dto.FindingsNotDetected {
		t.Fatalf("ordinary Nikto completion was treated as a timeout: %+v", result)
	}
}

func TestClassifyNiktoResultParsesReportedRequestCount(t *testing.T) {
	// Given: a completed Nikto summary with its authoritative request count.
	input := dto.ToolResult{ReturnCode: 0, Stdout: "- STATUS: Completed 8318 requests: currently in plugin 'Nikto Tests'\n" +
		"+ 8499 requests: 0 errors and 7 items reported on the remote host\n"}

	// When: the MCP boundary classifies the result.
	result := classifyToolResult("nikto_scan", input)

	// Then: the exact count and its parsed provenance are exposed.
	if result.HTTPRequests == nil || *result.HTTPRequests != 8499 || result.RequestCountSource != dto.RequestCountParsed {
		t.Fatalf("Nikto request count was not parsed: %+v", result)
	}
}

func TestClassifyNiktoResultSupportsCurrentProgressAndSingularFindingFormat(t *testing.T) {
	input := dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "- STATUS: Completed 8318 requests\n+ Scan terminated: 0 errors and 1 item reported on the remote host\n",
	}

	result := classifyToolResult("nikto_scan", input)

	if result.HTTPRequests == nil || *result.HTTPRequests != 8318 || result.RequestCountSource != dto.RequestCountParsed {
		t.Fatalf("current Nikto progress count was not parsed: %+v", result)
	}
	if result.FindingStatus != dto.FindingsDetected || result.ClassificationReason != "nikto_items_reported" {
		t.Fatalf("singular Nikto finding was not classified: %+v", result)
	}
}

func TestClassifyNucleiDryRunDoesNotReportFinding(t *testing.T) {
	input := dto.ToolResult{
		ReturnCode: 0,
		Stdout:     "dry run validated; tool was not executed",
		Execution:  dto.ExecutionMetadata{DryRun: true},
		NucleiPreview: &dto.NucleiPreviewMetadata{
			TemplatesMatched: 42, TargetRequestsSent: 0,
		},
	}

	result := classifyToolResult("nuclei_scan", input)

	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsUnknown || result.ClassificationReason != "dry_run_preview" {
		t.Fatalf("dry run was classified as target evidence: %+v", result)
	}
}

func TestClassifyToolResultDistinguishesObservationTypes(t *testing.T) {
	// Given: scanners that report different kinds of observations.
	tests := []struct {
		tool   string
		stdout string
		want   []string
	}{
		{tool: "nmap_scan", stdout: "3000/tcp open http", want: []string{"service"}},
		{tool: "whatweb_scan", stdout: "HTTPServer[Express]", want: []string{"technology"}},
		{tool: "ffuf_scan", stdout: `{"url":"https://example.test/admin"}`, want: []string{"content"}},
		{tool: "nuclei_scan", stdout: `{"template-id":"exposure"}`, want: []string{"vulnerability", "misconfiguration"}},
	}

	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			// When: the common MCP result is classified and serialized.
			result := classifyToolResult(test.tool, dto.ToolResult{ReturnCode: 0, Stdout: test.stdout})
			payload, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("marshal classified result: %v", err)
			}
			var object map[string]any
			if err := json.Unmarshal(payload, &object); err != nil {
				t.Fatalf("decode classified result: %v", err)
			}

			// Then: the result identifies what was detected without treating all output as a vulnerability.
			values, ok := object["finding_types"].([]any)
			if !ok {
				t.Fatalf("finding_types missing from %s result: %s", test.tool, payload)
			}
			got := make([]string, 0, len(values))
			for _, value := range values {
				got = append(got, value.(string))
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("finding_types=%v want=%v", got, test.want)
			}
		})
	}
}

func TestClassifyJWTResultExplainsMalformedInput(t *testing.T) {
	// Given: jwt_tool rejected a token that failed payload parsing before execution.
	input := dto.ToolResult{
		ReturnCode: 1,
		JWTAnalysis: &dto.JWTAnalysisMetadata{
			ParseStatus: dto.JWTMalformed, FailureStage: dto.JWTFailurePayloadJSON,
		},
	}

	// When: the MCP boundary classifies the tool result.
	result := classifyToolResult("jwt_analyze", input)

	// Then: execution failure and the parser failure stage remain distinct.
	if result.ExecutionStatus != dto.ExecutionFailed || result.FindingStatus != dto.FindingsUnknown || result.ClassificationReason != "jwt_payload_json_failed" {
		t.Fatalf("unexpected JWT classification: %+v", result)
	}
}

func TestClassifyJWTResultMarksMissingLiveTokenInconclusive(t *testing.T) {
	// Given: offline parsing succeeded, but jwt_tool could not obtain a token from the live target.
	input := dto.ToolResult{
		ReturnCode: 0,
		Stderr:     "Cannot find a valid JWT",
		JWTAnalysis: &dto.JWTAnalysisMetadata{
			ParseStatus: dto.JWTParsed,
		},
	}

	// When: the MCP boundary classifies the otherwise successful tool execution.
	result := classifyToolResult("jwt_analyze", input)

	// Then: successful execution is kept separate from the inconclusive live analysis.
	if result.ExecutionStatus != dto.ExecutionSucceeded || result.FindingStatus != dto.FindingsInconclusive || !result.PartialResults || result.ClassificationReason != "jwt_live_token_not_observed" {
		t.Fatalf("unexpected JWT live classification: %+v", result)
	}
}
