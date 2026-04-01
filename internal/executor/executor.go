// Package executor handles subprocess execution with streaming output support.
package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const DefaultTimeout = 180 * time.Second

// Result is the collected output from a finished command.
type Result struct {
	Stdout     string
	Stderr     string
	ReturnCode int
	TimedOut   bool
}

// Success returns true when the command completed without error,
// or timed-out but still produced useful output.
func (r *Result) Success() bool {
	if r.TimedOut {
		return r.Stdout != "" || r.Stderr != ""
	}
	return r.ReturnCode == 0
}

// Format returns a human-readable merged output suitable for MCP tool results.
func (r *Result) Format() string {
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
		sb.WriteString("\n\n[WARNING: timed out — partial results above]")
	}
	if sb.Len() == 0 {
		sb.WriteString("(no output)")
	}
	return sb.String()
}

// Line is a single output line from a streaming execution.
type Line struct {
	Stream string // "stdout" | "stderr"
	Text   string
}

// Run executes args and returns collected output.
// args[0] is the binary; if len==1, it is run via bash -c (shell mode).
func Run(ctx context.Context, timeout time.Duration, args []string) *Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := buildCmd(ctx, args)

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return &Result{Stderr: fmt.Sprintf("start: %v", err), ReturnCode: -1}
	}

	var (
		stdout, stderr strings.Builder
		mu             sync.Mutex
		wg             sync.WaitGroup
	)

	collect := func(r io.Reader, buf *strings.Builder) {
		defer wg.Done()
		sc := newScanner(r)
		for sc.Scan() {
			mu.Lock()
			buf.WriteString(sc.Text())
			buf.WriteByte('\n')
			mu.Unlock()
		}
	}

	wg.Add(2)
	go collect(stdoutPipe, &stdout)
	go collect(stderrPipe, &stderr)
	wg.Wait()

	_ = cmd.Wait()
	timedOut := ctx.Err() == context.DeadlineExceeded

	rc := 0
	if cmd.ProcessState != nil {
		rc = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		rc = -1
	}

	return &Result{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ReturnCode: rc,
		TimedOut:   timedOut,
	}
}

// Stream executes args and sends lines to the returned channel.
// The channel is closed when the process finishes or the context is cancelled.
// done receives the final Result after the channel is closed.
func Stream(ctx context.Context, timeout time.Duration, args []string) (<-chan Line, <-chan *Result) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	lines := make(chan Line, 256)
	done := make(chan *Result, 1)

	go func() {
		defer close(lines)
		defer close(done)

		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		cmd := buildCmd(ctx, args)
		stdoutPipe, _ := cmd.StdoutPipe()
		stderrPipe, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			done <- &Result{Stderr: fmt.Sprintf("start: %v", err), ReturnCode: -1}
			return
		}

		var (
			stdout, stderr strings.Builder
			mu             sync.Mutex
			wg             sync.WaitGroup
		)

		pipe := func(r io.Reader, stream string, buf *strings.Builder) {
			defer wg.Done()
			sc := newScanner(r)
			for sc.Scan() {
				text := sc.Text()
				mu.Lock()
				buf.WriteString(text)
				buf.WriteByte('\n')
				mu.Unlock()
				select {
				case lines <- Line{Stream: stream, Text: text}:
				case <-ctx.Done():
					return
				}
			}
		}

		wg.Add(2)
		go pipe(stdoutPipe, "stdout", &stdout)
		go pipe(stderrPipe, "stderr", &stderr)
		wg.Wait()

		_ = cmd.Wait()
		timedOut := ctx.Err() == context.DeadlineExceeded

		rc := 0
		if cmd.ProcessState != nil {
			rc = cmd.ProcessState.ExitCode()
		}
		if timedOut {
			rc = -1
		}

		done <- &Result{
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
			ReturnCode: rc,
			TimedOut:   timedOut,
		}
	}()

	return lines, done
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func buildCmd(ctx context.Context, args []string) *exec.Cmd {
	if len(args) == 1 {
		return exec.CommandContext(ctx, "bash", "-c", args[0])
	}
	return exec.CommandContext(ctx, args[0], args[1:]...)
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	return sc
}

// Which checks whether a binary exists on PATH.
func Which(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// WriteTemp writes content to a temp file and returns its path.
// The caller is responsible for removing it.
func WriteTemp(prefix, content string) (string, error) {
	f, err := os.CreateTemp("", prefix+"_*.rc")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return f.Name(), err
}
