package main

import (
	"errors"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestResolutionReceiptRejectsCandidateOutsideResolution(t *testing.T) {
	// Given: a receipt containing one explicitly resolved target.
	now := time.Date(2026, time.August, 29, 9, 0, 0, 0, time.UTC)
	result := dto.TargetResolutionResult{
		OriginalTarget:    "http://127.0.0.1:3000/",
		RecommendedTarget: "http://host.docker.internal:3000/",
		Candidates: []dto.TargetCandidate{
			{Target: "http://host.docker.internal:3000/", Reachable: true},
		},
	}
	issued, err := issueResolutionReceipt("secret", result, now)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}

	// When: a scanner selects a target outside the resolved candidates.
	_, err = verifyResolutionReceipt("secret", issued.Token, "http://192.0.2.10:3000/", now)

	// Then: the receipt is rejected as a target mismatch.
	if !errors.Is(err, errResolutionTargetMismatch) {
		t.Fatalf("expected target mismatch, got %v", err)
	}
}

func TestResolveTargetProvenanceRequiresReceiptForLoopback(t *testing.T) {
	// Given: a loopback scan request without a resolver receipt.
	request := dto.NmapRequest{Target: "127.0.0.1"}

	// When: target provenance is resolved at the execution boundary.
	_, err := resolveTargetProvenance(request, "secret", time.Now())

	// Then: execution is rejected until resolve_target has been used.
	if !errors.Is(err, errResolutionRequired) {
		t.Fatalf("expected resolution required, got %v", err)
	}
}
