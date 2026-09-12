package streaming

import (
	"encoding/json"
	"sync/atomic"

	"github.com/found-cake/kali-mcp-go/internal/executor"
)

type streamStatus struct {
	Code int
}

func observeFiveXXResponses(statuses <-chan streamStatus, threshold int, cancel func()) bool {
	count := 0
	for status := range statuses {
		if status.Code < 500 || status.Code > 599 {
			continue
		}
		count++
		if count >= threshold {
			cancel()
			return true
		}
	}
	return false
}

func MonitorFiveXXResponses(lines <-chan executor.Line, threshold int, cancel func()) (<-chan executor.Line, *atomic.Bool) {
	output := make(chan executor.Line, cap(lines))
	tripped := &atomic.Bool{}
	go func() {
		defer close(output)
		count := 0
		for line := range lines {
			output <- line
			status, ok := parseStreamStatus(line.Text)
			if !ok || status.Code < 500 || status.Code > 599 {
				continue
			}
			count++
			if count >= threshold && tripped.CompareAndSwap(false, true) {
				cancel()
			}
		}
	}()
	return output, tripped
}

func parseStreamStatus(line string) (streamStatus, bool) {
	var payload struct {
		Status     int `json:"status"`
		StatusCode int `json:"status_code"`
	}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return streamStatus{}, false
	}
	if payload.StatusCode != 0 {
		return streamStatus{Code: payload.StatusCode}, true
	}
	if payload.Status != 0 {
		return streamStatus{Code: payload.Status}, true
	}
	return streamStatus{}, false
}
