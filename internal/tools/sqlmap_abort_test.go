package tools

import (
	"slices"
	"testing"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestSQLMapPlanAppliesNativeAbortCodes(t *testing.T) {
	request := dto.SQLMapRequest{
		URL:        "https://example.test/?id=1",
		AbortCodes: "500,503",
	}

	plan, err := PrepareSQLMap(request)
	if err != nil {
		t.Fatalf("prepare SQLmap with abort codes: %v", err)
	}
	defer plan.Cleanup()

	args := plan.Args()
	index := slices.Index(args, "--abort-code")
	if index < 0 || index+1 >= len(args) || args[index+1] != "500,503" {
		t.Fatalf("native SQLmap abort codes missing: %v", args)
	}
}

func TestSQLMapAnalysisReportsNativeAbortCode(t *testing.T) {
	plan, err := PrepareSQLMap(dto.SQLMapRequest{
		URL:        "https://example.test/?id=1",
		AbortCodes: "500,503",
	})
	if err != nil {
		t.Fatalf("prepare SQLmap with abort codes: %v", err)
	}
	defer plan.Cleanup()

	analysis := plan.Analysis("[CRITICAL] aborting due to detected HTTP code '503'", "")
	if !slices.Equal(analysis.AbortCodes, []int{500, 503}) || analysis.AbortedOnHTTPCode != 503 {
		t.Fatalf("native abort metadata missing: %+v", analysis)
	}
}

func TestSQLMapPlanAppliesTypedComparisonAndPayloadOptions(t *testing.T) {
	// Given: SQLmap's native response oracles and payload selectors as typed fields.
	request := dto.SQLMapRequest{
		URL:            "https://example.test/?id=1",
		TrueString:     "Welcome back",
		FalseString:    "Access denied",
		TrueRegexp:     `user-[0-9]+`,
		TrueStatusCode: 200,
		PayloadPrefix:  "'))",
		PayloadSuffix:  "-- ",
		TestFilter:     "boolean-based blind",
	}

	// When: the SQLmap command is prepared.
	plan, err := PrepareSQLMap(request)
	if err != nil {
		t.Fatalf("prepare SQLmap typed options: %v", err)
	}
	defer plan.Cleanup()

	// Then: every value is forwarded through its official SQLmap flag.
	args := plan.Args()
	for flag, value := range map[string]string{
		"--string":      request.TrueString,
		"--not-string":  request.FalseString,
		"--regexp":      request.TrueRegexp,
		"--code":        "200",
		"--prefix":      request.PayloadPrefix,
		"--suffix":      request.PayloadSuffix,
		"--test-filter": request.TestFilter,
	} {
		index := slices.Index(args, flag)
		if index < 0 || index+1 >= len(args) || args[index+1] != value {
			t.Fatalf("SQLmap option %s=%q missing: %v", flag, value, args)
		}
	}
}
