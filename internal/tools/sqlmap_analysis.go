package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

var sqlmapResponsePattern = regexp.MustCompile(`(?m)^HTTP response \[#\d+\] \(([0-9]{3})[^)]*\):\r?\n`)

func (p *SQLMapPlan) Analysis(stdout, testParameters string) dto.SQLMapAnalysis {
	content, err := os.ReadFile(p.trafficFile)
	if err != nil {
		content = nil
	}
	analysis := analyzeSQLMapTraffic(content)
	analysis.Parameters = sqlmapParameterResults(stdout, testParameters)
	if sqlmapReportedNoInjection(stdout) {
		if analysis.ServerErrorResponses > 0 {
			analysis.ManualVerificationReasons = append(analysis.ManualVerificationReasons, "server_error_responses_observed")
		}
		if analysis.SignificantResponseDifference {
			analysis.ManualVerificationReasons = append(analysis.ManualVerificationReasons, "response_body_differences_observed")
		}
		if !analysis.TrafficAvailable || analysis.HTTPResponses == 0 {
			analysis.ManualVerificationReasons = append(analysis.ManualVerificationReasons, "response_traffic_unavailable")
		}
		if analysis.HTTPRequests > analysis.HTTPResponses {
			analysis.ManualVerificationReasons = append(analysis.ManualVerificationReasons, "incomplete_response_traffic")
		}
		analysis.ManualVerificationRecommended = len(analysis.ManualVerificationReasons) > 0
	}
	return analysis
}

func analyzeSQLMapTraffic(content []byte) dto.SQLMapAnalysis {
	analysis := dto.SQLMapAnalysis{
		TrafficAvailable: len(content) > 0,
		HTTPRequests:     strings.Count(string(content), "HTTP request [#"),
		StatusCounts:     make(map[string]int),
	}
	hashes := make(map[string]bool)
	responseMatches := sqlmapResponsePattern.FindAllSubmatchIndex(content, -1)
	minimumBodyBytes := -1
	for index, match := range responseMatches {
		status := string(content[match[2]:match[3]])
		analysis.StatusCounts[status]++
		analysis.HTTPResponses++
		if code, err := strconv.Atoi(status); err == nil && code >= 500 && code <= 599 {
			analysis.ServerErrorResponses++
		}
		sectionEnd := len(content)
		if index+1 < len(responseMatches) {
			sectionEnd = responseMatches[index+1][0]
		}
		section := content[match[1]:sectionEnd]
		if requestIndex := strings.Index(string(section), "HTTP request [#"); requestIndex >= 0 {
			section = section[:requestIndex]
		}
		body := responseBody(section)
		bodyBytes := len(body)
		if minimumBodyBytes < 0 || bodyBytes < minimumBodyBytes {
			minimumBodyBytes = bodyBytes
		}
		analysis.ResponseBodyMaxBytes = max(analysis.ResponseBodyMaxBytes, bodyBytes)
		digest := sha256.Sum256(body)
		hashes[hex.EncodeToString(digest[:])] = true
	}
	if minimumBodyBytes >= 0 {
		analysis.ResponseBodyMinBytes = minimumBodyBytes
	}
	analysis.ResponseBodyDeltaBytes = analysis.ResponseBodyMaxBytes - analysis.ResponseBodyMinBytes
	analysis.DistinctResponseBodies = len(hashes)
	analysis.SignificantResponseDifference = len(hashes) > 1 && analysis.ResponseBodyDeltaBytes >= 128
	if analysis.HTTPResponses > 0 {
		analysis.ServerErrorRatio = float64(analysis.ServerErrorResponses) / float64(analysis.HTTPResponses)
	}
	return analysis
}

func responseBody(section []byte) []byte {
	separator := []byte("\r\n\r\n")
	index := strings.Index(string(section), string(separator))
	if index < 0 {
		separator = []byte("\n\n")
		index = strings.Index(string(section), string(separator))
	}
	if index < 0 {
		return nil
	}
	return []byte(strings.TrimRight(string(section[index+len(separator):]), "\r\n"))
}

func sqlmapParameterResults(stdout, parameters string) []dto.SQLMapParameterResult {
	output := strings.ToLower(stdout)
	noInjection := sqlmapReportedNoInjection(stdout)
	var results []dto.SQLMapParameterResult
	for parameter := range strings.SplitSeq(parameters, ",") {
		name := strings.TrimSpace(parameter)
		if name == "" {
			continue
		}
		status := dto.SQLMapParameterInconclusive
		lowerName := strings.ToLower(name)
		if strings.Contains(output, "parameter: "+lowerName) || strings.Contains(output, "parameter '"+lowerName+"' is vulnerable") {
			status = dto.SQLMapParameterDetected
		} else if noInjection {
			status = dto.SQLMapParameterNotDetected
		}
		results = append(results, dto.SQLMapParameterResult{Name: name, Status: status})
	}
	return results
}

func sqlmapReportedNoInjection(stdout string) bool {
	output := strings.ToLower(stdout)
	return strings.Contains(output, "do not appear to be injectable") || strings.Contains(output, "does not seem to be injectable")
}
