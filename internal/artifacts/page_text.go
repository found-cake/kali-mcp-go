package artifacts

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

type pageText struct {
	data []byte
	text string
}

func (p pageText) len() int {
	if p.data != nil {
		return len(p.data)
	}
	return len(p.text)
}

func (p pageText) byteAt(index int64) byte {
	if p.data != nil {
		return p.data[index]
	}
	return p.text[index]
}

func (p pageText) countNewlines(start, end int) int {
	if p.data != nil {
		return bytes.Count(p.data[start:end], []byte{'\n'})
	}
	return strings.Count(p.text[start:end], "\n")
}

func (p pageText) indexNewline(start, end int) int {
	if p.data != nil {
		return bytes.IndexByte(p.data[start:end], '\n')
	}
	return strings.IndexByte(p.text[start:end], '\n')
}

func (p pageText) lastIndexNewline(start, end int) int {
	if p.data != nil {
		return bytes.LastIndexByte(p.data[start:end], '\n')
	}
	return strings.LastIndexByte(p.text[start:end], '\n')
}

func (p pageText) content(start, end int64) string {
	if p.data != nil {
		return string(p.data[start:end])
	}
	return strings.Clone(p.text[start:end])
}

func (p pageText) utf8End(start, end int64) int64 {
	if p.data != nil {
		return utf8PageEnd(p.data, start, end, int64(len(p.data)))
	}
	for end < int64(len(p.text)) && end > start && !utf8.RuneStart(p.text[end]) {
		end--
	}
	return end
}
