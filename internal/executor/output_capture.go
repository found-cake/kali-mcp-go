package executor

import (
	"strings"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const maximumRetainedOutputBytes = dto.MaximumRetainedOutputBytes

type outputCapture struct {
	builder   strings.Builder
	total     int
	limit     int
	truncated bool
}

func newOutputCapture(limit int) *outputCapture {
	return &outputCapture{limit: limit}
}

func (capture *outputCapture) Write(value []byte) (int, error) {
	capture.total += len(value)
	if capture.truncated || capture.builder.Len()+len(value) > capture.limit {
		capture.truncated = true
		return len(value), nil
	}
	return capture.builder.Write(value)
}

func (capture *outputCapture) WriteLine(value string, observedBytes int) {
	lineBytes := len(value) + 1
	capture.total += observedBytes
	if capture.truncated || capture.builder.Len()+lineBytes > capture.limit {
		capture.truncated = true
		return
	}
	capture.builder.WriteString(value)
	capture.builder.WriteByte('\n')
}

func (capture *outputCapture) Len() int {
	return capture.builder.Len()
}

func (capture *outputCapture) String() string {
	return capture.builder.String()
}

func (capture *outputCapture) TotalBytes() int {
	return capture.total
}

func (capture *outputCapture) Truncated() bool {
	return capture.truncated
}
