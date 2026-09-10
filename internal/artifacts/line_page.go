package artifacts

import (
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func readLinePage(reference dto.ArtifactRef, request dto.ArtifactReadRequest, section dto.ArtifactSection, payload pageText, now time.Time) (dto.ArtifactReadResult, error) {
	if request.Offset != 0 || request.Limit != 0 || reference.Encoding != dto.ArtifactEncodingUTF8 {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	startLine, lineCount, err := lineRange(request.StartLine, request.LineCount)
	if err != nil {
		return dto.ArtifactReadResult{}, err
	}
	total := payload.len()
	if total == 0 {
		if startLine != 1 {
			return dto.ArtifactReadResult{}, ErrInvalidPage
		}
		page := artifactPageMetadata(reference, request.ArtifactID, section, 0, now)
		page.StartLine = 1
		return page, nil
	}
	// A terminal newline ends the last line; it does not start another one.
	totalLines := 1 + payload.countNewlines(0, total-1)
	if startLine > totalLines {
		return dto.ArtifactReadResult{}, ErrInvalidPage
	}
	start := findLineStart(payload, startLine, totalLines)
	end, lines, truncated := boundedLineEnd(payload, start, lineCount)
	endLine := startLine + lines - 1
	page := artifactPageMetadata(reference, request.ArtifactID, section, int64(total), now)
	page.Content = payload.content(int64(start), int64(end))
	page.Offset = int64(start)
	page.NextOffset = int64(end)
	page.HasMore = end < total
	page.StartLine = startLine
	page.EndLine = endLine
	page.TotalLines = totalLines
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

func findLineStart(payload pageText, startLine, totalLines int) int {
	const blockSize = 4 * 1024
	if startLine == 1 {
		return 0
	}
	if startLine <= totalLines/2 {
		start, remaining := 0, startLine-1
		total := payload.len()
		for total-start > blockSize {
			lines := payload.countNewlines(start, start+blockSize)
			if lines >= remaining {
				break
			}
			start += blockSize
			remaining -= lines
		}
		for ; remaining > 0; remaining-- {
			start += payload.indexNewline(start, total) + 1
		}
		return start
	}
	end, remaining := payload.len()-1, totalLines-startLine+1
	for end > blockSize {
		lines := payload.countNewlines(end-blockSize, end)
		if lines >= remaining {
			break
		}
		end -= blockSize
		remaining -= lines
	}
	for ; remaining > 0; remaining-- {
		end = payload.lastIndexNewline(0, end)
	}
	return end + 1
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

func boundedLineEnd(payload pageText, start, lineCount int) (int, int, bool) {
	end, lines := start, 0
	total := payload.len()
	for lines < lineCount && end < total {
		lineEnd := total
		if newline := payload.indexNewline(end, total); newline >= 0 {
			lineEnd = end + newline + 1
		}
		if lineEnd-start > maximumPageSize {
			if end == start {
				end = int(payload.utf8End(int64(start), int64(start+maximumPageSize)))
				return end, 1, true
			}
			break
		}
		end = lineEnd
		lines++
	}
	return end, lines, false
}
