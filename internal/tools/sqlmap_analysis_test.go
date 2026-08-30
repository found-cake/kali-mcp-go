package tools

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSQLMapPlan_analysis_recommends_manual_verification_for_conflicting_traffic(t *testing.T) {
	// Given: SQLmap traffic with a normal response, a large 500 response, and an automated negative verdict.
	plan, err := PrepareSQLMap(dto.SQLMapRequest{URL: "https://example.com/?id=1", TestParameters: "id"})
	if err != nil {
		t.Fatalf("prepare sqlmap: %v", err)
	}
	defer plan.Cleanup()
	traffic := "HTTP request [#1]:\nGET /?id=1 HTTP/1.1\n\nHTTP response [#1] (200 OK):\nContent-Type: text/plain\n\nok\n\n" +
		"HTTP request [#2]:\nGET /?id=1%27 HTTP/1.1\n\nHTTP response [#2] (500 Internal Server Error):\nContent-Type: text/plain\n\n" + strings.Repeat("database-error-", 20) + "\n"
	if err := os.WriteFile(plan.trafficFile, []byte(traffic), 0o600); err != nil {
		t.Fatalf("write traffic fixture: %v", err)
	}

	// When: the redacted traffic summary is prepared.
	analysis := plan.Analysis("all tested parameters do not appear to be injectable", "id")

	// Then: request evidence is quantified and the negative verdict is marked for manual review.
	if analysis.HTTPRequests != 2 || analysis.HTTPResponses != 2 || analysis.StatusCounts["200"] != 1 || analysis.StatusCounts["500"] != 1 {
		t.Fatalf("unexpected HTTP summary: %+v", analysis)
	}
	if analysis.ServerErrorResponses != 1 || analysis.ServerErrorRatio != 0.5 || analysis.DistinctResponseBodies != 2 || analysis.ResponseBodyDeltaBytes == 0 {
		t.Fatalf("missing differential evidence: %+v", analysis)
	}
	if !analysis.ManualVerificationRecommended || !slices.Contains(analysis.ManualVerificationReasons, "server_error_responses_observed") || !slices.Contains(analysis.ManualVerificationReasons, "response_body_differences_observed") || len(analysis.Parameters) != 1 || analysis.Parameters[0].Status != dto.SQLMapParameterNotDetected {
		t.Fatalf("manual verification was not recommended: %+v", analysis)
	}
}
