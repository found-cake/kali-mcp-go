package executor

import (
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

const maximumProgressOutputBytes = 512

type outputProgress struct {
	mu    sync.Mutex
	count int
	last  string
}

func newOutputProgress() *outputProgress {
	return &outputProgress{}
}

func (p *outputProgress) observe(value string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	p.last = truncateProgressOutput(value)
	return p.count
}

func (p *outputProgress) snapshot() *dto.ProgressMetadata {
	p.mu.Lock()
	defer p.mu.Unlock()
	progress := &dto.ProgressMetadata{
		Phase:               dto.ProgressRunning,
		ObservedOutputItems: p.count,
		LastObservedOutput:  p.last,
		ResumeSupported:     false,
	}
	if p.count > 0 {
		progress.Checkpoint = fmt.Sprintf("output-item-%d", p.count)
	}
	return progress
}

func (r *Result) FinalizeProgress() {
	if r.Progress == nil {
		r.Progress = &dto.ProgressMetadata{}
	}
	r.Progress.Phase = progressPhase(r)
	r.Progress.HTTPRequests = r.HTTPRequests
	r.Progress.HTTPRequestBudget = r.Policy.TimeoutRequestBudget
}

func progressPhase(result *Result) dto.ProgressPhase {
	switch {
	case result.TimedOut:
		return dto.ProgressTimedOut
	case result.Cancelled:
		return dto.ProgressCancelled
	case result.ReturnCode == 0:
		return dto.ProgressCompleted
	default:
		return dto.ProgressFailed
	}
}

func truncateProgressOutput(value string) string {
	if len(value) <= maximumProgressOutputBytes {
		return value
	}
	end := maximumProgressOutputBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
