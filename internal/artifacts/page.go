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
	section, text, err := artifactSection(reference, payload, request.Section)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	if request.StartLine != 0 || request.LineCount != 0 {
		return readLinePage(reference, request, section, text, now)
	}
	return readBytePage(reference, request, section, text, now)
}

func artifactSection(reference dto.ArtifactRef, payload []byte, requested dto.ArtifactSection) (dto.ArtifactSection, pageText, error) {
	section := requested
	if section == "" {
		section = dto.ArtifactSectionRaw
	}
	if section == dto.ArtifactSectionRaw {
		return section, pageText{data: payload}, nil
	}
	if section != dto.ArtifactSectionStdout && section != dto.ArtifactSectionStderr {
		return "", pageText{}, ErrInvalidPage
	}
	if reference.Kind != "tool-result-json" || reference.Encoding != dto.ArtifactEncodingUTF8 {
		return "", pageText{}, ErrInvalidPage
	}
	var result struct {
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return "", pageText{}, ErrInvalidPage
	}
	if section == dto.ArtifactSectionStdout {
		return section, pageText{text: result.Stdout}, nil
	}
	return section, pageText{text: result.Stderr}, nil
}

func readBytePage(reference dto.ArtifactRef, request dto.ArtifactReadRequest, section dto.ArtifactSection, payload pageText, now time.Time) (dto.ArtifactReadResult, error) {
	limit, err := pageSize(request.Limit)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	total := int64(payload.len())
	if request.Offset < 0 || request.Offset > total {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	if reference.Encoding == dto.ArtifactEncodingUTF8 && request.Offset < total && !utf8.RuneStart(payload.byteAt(request.Offset)) {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	end := min(request.Offset+int64(limit), total)
	if reference.Encoding == dto.ArtifactEncodingUTF8 {
		end = payload.utf8End(request.Offset, end)
	}
	page := artifactPageMetadata(reference, request.ArtifactID, section, total, now)
	if reference.Encoding == dto.ArtifactEncodingBase64 {
		page.Content = pageContent(payload.data[request.Offset:end], reference.Encoding)
	} else {
		page.Content = payload.content(request.Offset, end)
	}
	page.Offset = request.Offset
	page.NextOffset = end
	page.HasMore = end < total
	return page, nil
}

func pageContent(payload []byte, encoding dto.ArtifactEncoding) string {
	if encoding == dto.ArtifactEncodingBase64 {
		return base64.StdEncoding.EncodeToString(payload)
	}
	return string(payload)
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
