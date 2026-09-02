package dto

import (
	"fmt"
	"strings"
)

func (r *ToolResult) Format() string {
	var sb strings.Builder
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
		fmt.Fprintf(&sb, "\n\n[evidence group: %s]", r.Evidence.GroupID)
		for _, artifact := range r.Evidence.Artifacts {
			fmt.Fprintf(&sb, "\n- %s (%s): %s", artifact.Relation, artifact.Kind, artifact.ID)
		}
	}
	if summary, err := r.inlineStructuredSummary(); err != nil {
		fmt.Fprintf(&sb, "\n\n[structured summary unavailable: %v]", err)
	} else if summary != "" {
		sb.WriteString("\n\n[structured summary]\n")
		sb.WriteString(summary)
	}
	if sb.Len() == 0 {
		sb.WriteString("(no output)")
	}
	return sb.String()
}
