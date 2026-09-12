package main

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const jwtResponseCodeMarker = " Response Code: "

type jwtAttemptCounts struct {
	tested       int
	accepted     int
	rejected     int
	inconclusive int
}

func (counts *jwtAttemptCounts) observe(statusCode int, canaryConfigured, canaryMatched bool) {
	counts.tested++
	switch {
	case statusCode == 401 || statusCode == 403:
		counts.rejected++
	case canaryConfigured && canaryMatched:
		counts.accepted++
	default:
		counts.inconclusive++
	}
}

func attachJWTLiveAnalysis(result *dto.ToolResult) {
	if !slices.Contains(result.Execution.ArgvRedacted, "-t") {
		return
	}
	live, observed := parseJWTLiveAnalysis(result.Stdout+"\n"+result.Stderr, slices.Contains(result.Execution.ArgvRedacted, "-cv"))
	if !observed {
		return
	}
	result.JWTLiveAnalysis = &live
	if live.Requests > 0 {
		count := live.Requests
		result.HTTPRequests = &count
		result.RequestCountSource = dto.RequestCountParsed
	}
}

func classifyJWTLiveFinding(result *dto.ToolResult) {
	live := result.JWTLiveAnalysis
	switch {
	case !live.Completed:
		result.FindingStatus = dto.FindingsInconclusive
		result.PartialResults = true
		result.ClassificationReason = "jwt_live_scan_incomplete"
	case !live.BaselineAccepted:
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "jwt_live_baseline_not_accepted"
	case live.MutationsAccepted > 0:
		result.FindingStatus = dto.FindingsDetected
		result.ClassificationReason = "jwt_live_mutation_accepted"
	case live.ControlsAccepted > 0:
		result.FindingStatus = dto.FindingsDetected
		result.ClassificationReason = "jwt_live_control_accepted"
	case live.MutationsTested == 0:
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "jwt_live_no_mutations_observed"
	case live.MutationsInconclusive > 0 || live.ControlsInconclusive > 0:
		result.FindingStatus = dto.FindingsInconclusive
		result.ClassificationReason = "jwt_live_responses_inconclusive"
	default:
		result.FindingStatus = dto.FindingsNotDetected
		result.ClassificationReason = "jwt_live_mutations_rejected"
	}
}

func parseJWTLiveAnalysis(output string, canaryConfigured bool) (dto.JWTLiveAnalysisMetadata, bool) {
	live := dto.JWTLiveAnalysisMetadata{}
	statusCounts := make(map[int]int)
	mutationPhase := false
	canaryMatched := false
	baselineAccepted := 0
	controls := jwtAttemptCounts{}
	mutations := jwtAttemptCounts{}
	for line := range strings.Lines(output) {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "LAUNCHING SCAN:"):
			mutationPhase = true
		case strings.HasPrefix(trimmed, "[+] FOUND ") && strings.HasSuffix(trimmed, " in response:"):
			canaryMatched = true
		case strings.Contains(trimmed, jwtResponseCodeMarker):
			label, statusCode, ok := parseJWTResponseLine(trimmed)
			if !ok {
				canaryMatched = false
				continue
			}
			live.Requests++
			statusCounts[statusCode]++
			if mutationPhase {
				mutations.observe(statusCode, canaryConfigured, canaryMatched)
			} else if jwtBaselineLabel(label) {
				live.BaselineRequests++
				if jwtBaselineAccepted(statusCode, canaryConfigured, canaryMatched) {
					baselineAccepted++
				}
			} else if strings.Contains(label, "Prescan:") {
				controls.observe(statusCode, canaryConfigured, canaryMatched)
			}
			canaryMatched = false
		}
	}
	live.Completed = strings.Contains(output, "Scanning mode completed:")
	live.BaselineAccepted = live.BaselineRequests > 0 && baselineAccepted == live.BaselineRequests
	live.ControlsTested = controls.tested
	live.ControlsAccepted = controls.accepted
	live.ControlsRejected = controls.rejected
	live.ControlsInconclusive = controls.inconclusive
	live.MutationsTested = mutations.tested
	live.MutationsAccepted = mutations.accepted
	live.MutationsRejected = mutations.rejected
	live.MutationsInconclusive = mutations.inconclusive
	statusCodes := make([]int, 0, len(statusCounts))
	for statusCode := range statusCounts {
		statusCodes = append(statusCodes, statusCode)
	}
	sort.Ints(statusCodes)
	for _, statusCode := range statusCodes {
		live.StatusCodes = append(live.StatusCodes, dto.JWTHTTPStatusCount{StatusCode: statusCode, Count: statusCounts[statusCode]})
	}
	return live, live.Requests > 0 || live.Completed
}

func parseJWTResponseLine(line string) (string, int, bool) {
	marker := strings.Index(line, jwtResponseCodeMarker)
	if marker < 0 {
		return "", 0, false
	}
	prefix := line[:marker]
	separator := strings.IndexByte(prefix, ' ')
	if separator < 0 || !strings.HasPrefix(prefix, "jwttool_") {
		return "", 0, false
	}
	fields := strings.Fields(line[marker+len(jwtResponseCodeMarker):])
	if len(fields) == 0 {
		return "", 0, false
	}
	statusCode, err := strconv.Atoi(strings.TrimSuffix(fields[0], ","))
	if err != nil || statusCode < 100 || statusCode > 599 {
		return "", 0, false
	}
	return prefix[separator+1:], statusCode, true
}

func jwtBaselineLabel(label string) bool {
	return label == "Sending token" || strings.Contains(label, "Prescan: original token") || strings.Contains(label, "Prescan: repeat original token")
}

func jwtBaselineAccepted(statusCode int, canaryConfigured, canaryMatched bool) bool {
	if statusCode < 200 || statusCode >= 400 {
		return false
	}
	return !canaryConfigured || canaryMatched
}
