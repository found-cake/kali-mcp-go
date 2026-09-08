package artifacts

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

type rawPageSource struct {
	reference dto.ArtifactRef
	reader    io.ReaderAt
	total     int64
}

func (s *Store) readRawBytePage(request dto.ArtifactReadRequest, now time.Time) (dto.ArtifactReadResult, error) {
	artifact, err := s.lookup(request.ArtifactID, now)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	file, err := os.Open(artifact.path)
	if err != nil {
		s.forget(request.ArtifactID)
		return dto.ArtifactReadResult{}, ErrNotFound
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		s.forget(request.ArtifactID)
		return dto.ArtifactReadResult{}, ErrNotFound
	}
	page, err := readRawBytePage(rawPageSource{
		reference: artifact.reference,
		reader:    file,
		total:     info.Size(),
	}, request, now)
	if errors.Is(err, ErrNotFound) {
		s.forget(request.ArtifactID)
	}
	return page, err
}

func readRawBytePage(source rawPageSource, request dto.ArtifactReadRequest, now time.Time) (dto.ArtifactReadResult, error) {
	limit, err := pageSize(request.Limit)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	if request.Offset < 0 || request.Offset > source.total {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	contentLength := min(int64(limit), source.total-request.Offset)
	readLength := contentLength
	if source.reference.Encoding == dto.ArtifactEncodingUTF8 && request.Offset+contentLength < source.total {
		readLength++
	}
	payload := make([]byte, int(readLength))
	if readLength > 0 {
		readBytes, readErr := source.reader.ReadAt(payload, request.Offset)
		atEOF := request.Offset+int64(readBytes) == source.total
		if readBytes != len(payload) || (readErr != nil && !(errors.Is(readErr, io.EOF) && atEOF)) {
			return dto.ArtifactReadResult{}, ErrNotFound
		}
	}
	if source.reference.Encoding == dto.ArtifactEncodingUTF8 && contentLength > 0 && !utf8.RuneStart(payload[0]) {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	pageLength := contentLength
	if source.reference.Encoding == dto.ArtifactEncodingUTF8 {
		pageLength = utf8PageEnd(payload, 0, contentLength, int64(len(payload)))
	}
	content := string(payload[:pageLength])
	if source.reference.Encoding == dto.ArtifactEncodingBase64 {
		content = base64.StdEncoding.EncodeToString(payload[:pageLength])
	}
	nextOffset := request.Offset + pageLength
	page := artifactPageMetadata(source.reference, request.ArtifactID, dto.ArtifactSectionRaw, source.total, now)
	page.Content = content
	page.Offset = request.Offset
	page.NextOffset = nextOffset
	page.HasMore = nextOffset < source.total
	return page, nil
}
