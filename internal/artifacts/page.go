package artifacts

import (
	"encoding/base64"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const (
	defaultPageSize  = 16 * 1024
	minimumPageSize  = 256
	maximumPageSize  = 64 * 1024
	defaultLineCount = 100
	maximumLineCount = 500
)

func (s *Store) ReadPage(request dto.ArtifactReadRequest, now time.Time) (dto.ArtifactReadResult, error) {
	if (request.Section == "" || request.Section == dto.ArtifactSectionRaw) && request.StartLine == 0 && request.LineCount == 0 {
		return s.readRawBytePage(request, now)
	}
	reference, payload, err := s.Read(request.ArtifactID, now)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	section, payload, err := artifactSection(reference, payload, request.Section)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	if request.StartLine != 0 || request.LineCount != 0 {
		return readLinePage(reference, request, section, payload, now)
	}
	return readBytePage(reference, request, section, payload, now)
}

func artifactSection(reference dto.ArtifactRef, payload []byte, requested dto.ArtifactSection) (dto.ArtifactSection, []byte, error) {
	section := requested
	if section == "" {
		section = dto.ArtifactSectionRaw
	}
	if section == dto.ArtifactSectionRaw {
		return section, payload, nil
	}
	if section != dto.ArtifactSectionStdout && section != dto.ArtifactSectionStderr {
		return "", nil, ErrInvalidPage
	}
	if reference.Kind != "tool-result-json" || reference.Encoding != dto.ArtifactEncodingUTF8 {
		return "", nil, ErrInvalidPage
	}
	var result struct {
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", nil, ErrInvalidPage
	}
	if section == dto.ArtifactSectionStdout {
		return section, []byte(result.Stdout), nil
	}
	return section, []byte(result.Stderr), nil
}

func readBytePage(reference dto.ArtifactRef, request dto.ArtifactReadRequest, section dto.ArtifactSection, payload []byte, now time.Time) (dto.ArtifactReadResult, error) {
	limit, err := pageSize(request.Limit)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	total := int64(len(payload))
	if request.Offset < 0 || request.Offset > total {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	if reference.Encoding == dto.ArtifactEncodingUTF8 && request.Offset < total && !utf8.RuneStart(payload[request.Offset]) {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	end := min(request.Offset+int64(limit), total)
	if reference.Encoding == dto.ArtifactEncodingUTF8 {
		end = utf8PageEnd(payload, request.Offset, end, total)
	}
	content := string(payload[request.Offset:end])
	if reference.Encoding == dto.ArtifactEncodingBase64 {
		content = base64.StdEncoding.EncodeToString(payload[request.Offset:end])
	}
	page := artifactPageMetadata(reference, request.ArtifactID, section, int64(len(payload)), now)
	page.Content = content
	page.Offset = request.Offset
	page.NextOffset = end
	page.HasMore = end < total
	return page, nil
}

func readLinePage(reference dto.ArtifactRef, request dto.ArtifactReadRequest, section dto.ArtifactSection, payload []byte, now time.Time) (dto.ArtifactReadResult, error) {
	if request.Offset != 0 || request.Limit != 0 || reference.Encoding != dto.ArtifactEncodingUTF8 {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	startLine, lineCount, err := lineRange(request.StartLine, request.LineCount)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	starts := lineStarts(payload)
	if len(starts) == 0 {
		if startLine != 1 {
			return dto.ArtifactReadResult{}, ErrInvalidPage
		}
		page := artifactPageMetadata(reference, request.ArtifactID, section, 0, now)
		page.StartLine = 1
		return page, nil
	}
	if startLine > len(starts) {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	start := starts[startLine-1]
	end, endLine, truncated := boundedLineEnd(payload, starts, startLine, lineCount)
	page := artifactPageMetadata(reference, request.ArtifactID, section, int64(len(payload)), now)
	page.Content = string(payload[start:end])
	page.Offset = int64(start)
	page.NextOffset = int64(end)
	page.HasMore = end < len(payload)
	page.StartLine = startLine
	page.EndLine = endLine
	page.TotalLines = len(starts)
	page.LineTruncated = truncated
	if page.HasMore {
		if truncated {
			page.NextLine = startLine
		} else {
			page.NextLine = endLine + 1
		}
	}
	return page, nil
}

func artifactPageMetadata(reference dto.ArtifactRef, artifactID string, section dto.ArtifactSection, totalBytes int64, now time.Time) dto.ArtifactReadResult {
	expiresIn := max(int64(reference.ExpiresAt.Sub(now)/time.Second), 0)
	return dto.ArtifactReadResult{
		ArtifactID: artifactID, TotalBytes: totalBytes, Section: section, ExpiresAt: reference.ExpiresAt,
		ExpiresInSeconds: expiresIn, ExpiringSoon: expiresIn <= int64(artifactExpiryWarning/time.Second),
		SourceCallID: reference.SourceCallID, MediaType: reference.MediaType, Encoding: reference.Encoding,
		RedactionState: reference.RedactionState, Relation: reference.Relation,
	}
}

func lineRange(startLine, lineCount int) (int, int, error) {
	if startLine == 0 {
		startLine = 1
	}
	if lineCount == 0 {
		lineCount = defaultLineCount
	}
	if startLine < 1 || lineCount < 1 || lineCount > maximumLineCount {
		return 0, 0, ErrInvalidPage
	}
	return startLine, lineCount, nil
}

func lineStarts(payload []byte) []int {
	if len(payload) == 0 {
		return nil
	}
	starts := []int{0}
	for index, value := range payload {
		if value == '\n' && index+1 < len(payload) {
			starts = append(starts, index+1)
		}
	}
	return starts
}

func boundedLineEnd(payload []byte, starts []int, startLine, lineCount int) (int, int, bool) {
	start := starts[startLine-1]
	end := start
	endLine := startLine - 1
	lastLine := min(startLine+lineCount-1, len(starts))
	for line := startLine; line <= lastLine; line++ {
		lineEnd := len(payload)
		if line < len(starts) {
			lineEnd = starts[line]
		}
		if lineEnd-start > maximumPageSize {
			if end == start {
				end = int(utf8PageEnd(payload, int64(start), int64(start+maximumPageSize), int64(len(payload))))
				return end, startLine, true
			}
			break
		}
		end = lineEnd
		endLine = line
	}
	return end, endLine, false
}

func utf8PageEnd(payload []byte, start, end, total int64) int64 {
	for end < total && end > start && !utf8.RuneStart(payload[end]) {
		end--
	}
	return end
}

func pageSize(requested int) (int, error) {
	if requested == 0 {
		return defaultPageSize, nil
	}
	if requested < minimumPageSize || requested > maximumPageSize {
		return 0, ErrInvalidPage
	}
	return requested, nil
}
