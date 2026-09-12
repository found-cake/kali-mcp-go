package dto

import (
	"fmt"
	"strings"
)

func (r *ToolResult) Format() string {
	var sb strings.Builder
	size := len(r.Stdout) + len(r.Stderr)
	if r.Stdout != "" && r.Stderr != "" {
		size += len("\n[stderr]\n")
	}
	sb.Grow(size)
	if r.Stdout != "" {
		sb.WriteString(r.Stdout)
	}
	if r.Stderr != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n[stderr]\n")
		}
		sb.WriteString(r.Stderr)
	}
	if r.TimedOut {
		if r.PartialResults || r.Stdout != "" || r.Stderr != "" {
			sb.WriteString("\n\n[WARNING: timed out — partial results above]")
		} else {
			sb.WriteString("[WARNING: timed out with no output]")
		}
	}
	if r.OutputTruncated {
		sb.WriteString("\n\n[output truncated — read the result artifact for full retained output]")
	}
	if r.Evidence != nil && len(r.Evidence.Artifacts) > 0 {
		sb.WriteString("\n\n[evidence group: ")
		sb.WriteString(r.Evidence.GroupID)
		sb.WriteByte(']')
		for _, artifact := range r.Evidence.Artifacts {
			sb.WriteString("\n- ")
			sb.WriteString(string(artifact.Relation))
			sb.WriteString(" (")
			sb.WriteString(artifact.Kind)
			sb.WriteString("): ")
			sb.WriteString(artifact.ID)
		}
	}
	if summary, err := r.inlineStructuredSummary(); err != nil {
		sb.WriteString(fmt.Sprintf("\n\n[structured summary unavailable: %v]", err))
	} else if len(summary) != 0 {
		sb.WriteString("\n\n[structured summary]\n")
		sb.Write(summary)
	}
	if sb.Len() == 0 {
		sb.WriteString("(no output)")
	}
	return sb.String()
}
